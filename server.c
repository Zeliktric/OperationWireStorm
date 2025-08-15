#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <errno.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <signal.h>

#pragma region Macros

#define BUFFER_SIZE 256000 // 256KB
#define SOURCE_PORT 33333
#define DEST_PORT 44444

#define MAGIC_BYTE 0xCC
#define HEADER_SIZE 8
#define PADDING 0x00
#define BINARY_LEN 8

#pragma endregion
#pragma region Global Variables

int gPacketCount = 0,
    gSocketCount = 0;

bool gPacketValidated = true,
    gDebug = false;

volatile bool gLoop = true;

// File descriptors for source & dest sockets and connections
int gSourceSocket, gDestSocket;
int gSourceConn, gDestConn;

#pragma endregion
#pragma region Server Close

// Closes all of the file descriptors to avoid leaks
void CloseFds()
{
    close(gSourceSocket);
    close(gDestSocket);
    close(gSourceConn);
    close(gDestConn);
}

// Called when the program receives 'SIGINT'
void Handler(int signal)
{
    // Stops the gLoop in main to stop new requests from being accepted
	gLoop = false;

    CloseFds();

    printf("\nServer stopped.\n");
}

#pragma endregion
#pragma region Utility Methods

/**
 * Utility method for converting an unsigned integer to a binary array representation.
 * 
 * Adapted from: https://stackoverflow.com/a/31578829.
 * 
 * @param[in] value The unsigned integer to convert.
 * @param[in] count The length of the binary array.
 * @param[out] binArray The binary array representation of the unsigned integer.
 * 
 */
void UIntToBinArray(uint16_t value, int count, int* binArray)
{
    uint16_t mask = 1U << (count-1);

    for (int i = 0; i < count; i++)
    {
        binArray[i] = (value & mask) ? 1 : 0;
        value <<= 1;
    }
}

/**
 * Utility method to add two numbers together in one's complement.
 * 
 * Adapted from: https://stackoverflow.com/a/67358741
 * 
 * @param[in] a The first number in the addition.
 * @param[in] b The second number in the addition.
 */
uint16_t OnesComplementSum(uint16_t a, uint16_t b)
{
    uint32_t sum = a + b; // uint32_t to allow for potential overflow
    return (sum & 0xFFFF) + (sum >> 16);
}

/**
 * Utility method to add a socket's file descriptor to epoll.
 * 
 * @param[in] epfd The epoll file descriptor.
 * @param[in] fd The file descriptor of the socket to add.
 */
void AddSocket(int epfd, int fd)
{
    struct epoll_event event;

    event.events = EPOLLIN;
    event.data.fd = fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event);

    gSocketCount++;
}

#pragma endregion
#pragma region Process Packet

/**
 * Determines whether a packet is valid or not by the given rules:
 * 
 * 1) Magic byte must be correct.
 * 
 * 2) Data length must match actual length of the data.
 * 
 * 3) Header format is correct.
 * 
 * 4) Checksum is correct if the sensitive bit is 1.
 * 
 * @param[in] data The pointer to the packet that was read from the source socket.
 * @param[in] length The length (in bytes) of the packet.
 */
void ProcessPacket(unsigned char *data, int length)
{
    gPacketValidated = true;

    // Validate the magic byte field
    if (data[0] != MAGIC_BYTE)
    {
        if (gDebug) printf("Magic Byte Error. Received %02x, expecting %02x\n", data[0], MAGIC_BYTE);
        gPacketValidated = false;
    }
    else if (gDebug) printf("Magic Byte Validated (%02x).\n", data[0]);

    // Check the options field for whether the message is sensitive or not
    if (gPacketValidated)
    {
        int digits[8];
        UIntToBinArray(data[1], 8, digits);

        printf("Options Bit '1' = %d. %s\n", digits[1], digits[1] == 1 ? "Computing and validating checksum..." : "");

        // Validate options padding
        for (int i = 2; i < 8; i++)
        {
            if (digits[i] != PADDING)
            {
                if (gDebug) printf("Options Bit '%d' Padding Error. Received %01x, expecting %01x\n", i, digits[i], PADDING);
                gPacketValidated = false;
                break;
            }
            else if (gDebug) printf("Options Bit '%d' Padding Vaidated (%01x).\n", i, digits[i]);
        }

        if (gPacketValidated && digits[1] == 1)
        {
            // Compute and validate the checksum

            uint16_t checksum = (data[4] << 8) + data[5]; // unsigned + network byte order
            
            // Keep track of original checksum to modify 'data' after computing checksum
            uint16_t checksum1 = data[4];
            uint16_t checksum2 = data[5];
            
            // "For purposes of computing the checksum, the value of the checksum field is filled with `0xCC` bytes."
            data[4] = MAGIC_BYTE;
            data[5] = MAGIC_BYTE;

            // Compute the checksum
            uint16_t prevValue = 0x00;
            for (int i = 0; i < length; i += 2)
            {
                prevValue = OnesComplementSum(prevValue, (data[i] << 8) + data[i+1]);
            }
            
            // Invert the bits (one's complement)
            uint16_t computedChecksum = ~prevValue;

            // Set the original checksum back
            data[4] = checksum1;
            data[5] = checksum2;

            if (computedChecksum != checksum)
            {
                if (gDebug) printf("Checksum Error. Received %04x, expecting %04x\n", checksum, computedChecksum);
                gPacketValidated = false;
            }
            else if (gDebug) printf("Checksum Validated (%04x).\n", checksum);
        }
    }

    if (gPacketValidated)
    {
        // Validate the padding in the header
        if (data[6] != PADDING || data[7] != PADDING)
        {
            if (gDebug) printf("Padding Error. Received %02x, expecting %02x\n", data[6] != PADDING ? data[6] : data[7], PADDING);
            gPacketValidated = false;
        }
        else if (gDebug) printf("Padding Validated (%02x).\n", data[6] != PADDING ? data[6] : data[7]);
    }

    if (gPacketValidated)
    {
        // Validate data length in the header
        uint16_t data_length = (data[2] << 8) + data[3]; // unsigned + network byte order
        int acc_data_length = length - HEADER_SIZE;

        if (data_length != acc_data_length)
        {
            if (gDebug) printf("Data Length Error. Received %u, expecting %d.\n", data_length, acc_data_length);
            gPacketValidated = false;
        }
        else if (gDebug) printf("Data Length Validated (%u).\n", data_length);
    }

    printf(gPacketValidated ? "Packet %d validated!\n\n" : "Packet %d not validated!\n\n", gPacketCount);

    gPacketCount++;
}

#pragma endregion
#pragma region Send Packet

/**
 * Sends a packet to the specified destination client.
 * 
 * @param[in] data The pointer to the packet that was read from the source socket.
 * @param[in] length The length (in bytes) of the packet.
 * @param[in] client The file descriptor of the client to send the packet to.
 */
void SendPacket(unsigned char *data, int length, int client)
{
    ssize_t fs = send(client, data, length, MSG_NOSIGNAL);
    printf("Sent data to: '%d' (%d bytes)\n\n", client, length);

    if (fs == -1) printf("SendPacket Error: %s (%d)\n", strerror(errno), errno);
}

#pragma endregion
#pragma region Print Packet

/**
 * Utility/Debugging method for printing raw packet data.
 * 
 * Adapted from: University coursework.
 * 
 * @param[in] data The pointer to the packet that was read from the source socket.
 * @param[in] length The length (in bytes) of the packet.
 */
void PrintPacket(unsigned char *data, int length)
{
    printf(" === PACKET %ld HEADER ===\n", gPacketCount);

    for (int i = 0; i < HEADER_SIZE; i++)
    {
        printf("%02x ", data[i]);
    }

    printf("\n === PACKET %ld DATA == \n", gPacketCount);
    // Decode Packet Data (Skipping over the header)
    int data_bytes = length - HEADER_SIZE;
    const unsigned char *payload = data + HEADER_SIZE;
    const static int output_sz = 20; // Output this many bytes at a time

    while (data_bytes > 0)
    {
        int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;

        // Print data in raw hexadecimal form
        for (int i = 0; i < output_sz; i++)
        {
            if (i < output_bytes)
            {
                printf("%02x ", payload[i]);
            }
            else
            {
                printf("   "); // Maintain padding for partial lines
            }
        }
        printf ("| ");

        // Print data in ascii form
        for (int i = 0; i < output_bytes; i++) {
            char byte = payload[i];
            if (byte > 31 && byte < 127)
            {
                // Byte is in printable ascii range
                printf("%c", byte);
            }
            else
            {
                printf(".");
            }
        }

        printf("\n");
        payload += output_bytes;
        data_bytes -= output_bytes;
    }
    printf("\n");
}

#pragma endregion
#pragma region Main

int main(int argc, char *argv[])
{
    // Addresses for the source & dest sockets and clients
    struct sockaddr_in sourceAddr, destAddr, sourceClientAddr, destClientAddr;
    socklen_t sourceClientAddrLen = sizeof(sourceClientAddr);
    socklen_t destClientAddrLen = sizeof(destClientAddr);
    
    // Initialise buffer
    unsigned char buffer[BUFFER_SIZE];
    int recvlen;

    bool debugPrint = false;

    // Verifying command-line arguments
    if (argc >= 1 && argc <= 3)
    {
        for (int i = 1; i < argc; i++)
        {
            if (strcmp(argv[i], "-d") == 0) 
            {
                gDebug = true;
                printf("Debug: Packet Validation Information\n");
            }
            else if (strcmp(argv[i], "-p") == 0) 
            {
                debugPrint = true;
                printf("Debug: Raw Packet Data\n");
            }
            else
            {
                printf("Error: Invalid command-line argument. Expecting one of '-d', '-p'.\n");
                exit(EXIT_FAILURE);
            }
        }
    }
    else
    {
        printf("Error: too many command-line arguments\n");
        exit(EXIT_FAILURE);
    }

    // Create source & dest sockets
    if ((gSourceSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
		printf("Error: cannot create source socket\n");
		exit(EXIT_FAILURE);
	}
    if ((gDestSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
		printf("Error: cannot create dest socket\n");
		exit(EXIT_FAILURE);
	}
    
    // Set source address with the source port
    sourceAddr.sin_family = AF_INET;
    sourceAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    sourceAddr.sin_port = htons(SOURCE_PORT);

    // Set dest address with the dest port
    destAddr.sin_family = AF_INET;
    destAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    destAddr.sin_port = htons(DEST_PORT);

    // Bind source & dest sockets with their respective addresses
    if (bind(gSourceSocket, (struct sockaddr *)&sourceAddr, sizeof(sourceAddr)) < 0)
    {
		printf("Error: source bind failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
    if (bind(gDestSocket, (struct sockaddr *)&destAddr, sizeof(destAddr)) < 0)
    {
		printf("Error: dest bind failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

    // Start listening on source & dest sockets
    if (listen(gSourceSocket, 0) < 0)
    {
        printf("Error: source listen failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (listen(gDestSocket, SOMAXCONN) < 0)
    {
        printf("Error: dest listen failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, Handler);

    printf("Server started.\nWaiting on port %d and %d\n\n", SOURCE_PORT, DEST_PORT);

    int epfd = epoll_create1(0);
    if (epfd < 0)
    {
        printf("Error: epoll_create1 failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    AddSocket(epfd, gSourceSocket);
    AddSocket(epfd, gDestSocket);

    struct epoll_event events[gSocketCount];

    while (gLoop)
    {   
        // Wait for a file descriptor to have new activity (incoming connection)
        int n = epoll_wait(epfd, events, gSocketCount, -1);
        if (n < 0)
        {
            // Ignore the 'Interrupted system call' error when the user initiates it
            if (errno == EINTR) break;

            printf("Error: epoll_wait failed: %s\n", strerror(errno));
            CloseFds();
            
            exit(EXIT_FAILURE);
        }

        for (int i = 0; i < n; i++)
        {
            // Check whether the event is EPOLLIN
            bool incomingConn = events[i].events & EPOLLIN;
            if (!incomingConn) continue;

            if (events[i].data.fd == gSourceSocket) 
            {
                // New source connection (to read from)
                gSourceConn = accept(gSourceSocket, (struct sockaddr *)&sourceClientAddr, &sourceClientAddrLen);
                printf("(%d) Source connection accepted from %s:%d\n", i, inet_ntoa(sourceClientAddr.sin_addr), ntohs(sourceClientAddr.sin_port));
                
                // Read the packet sent
                recvlen = read(gSourceConn, buffer, sizeof(buffer));
                printf("Received packet %d (%d bytes)\n\n", gPacketCount, recvlen);

                if (debugPrint) PrintPacket(buffer, recvlen);
                ProcessPacket(buffer, recvlen);
            }
            else if (events[i].data.fd == gDestSocket)
            {
                // New dest connection (to write to)
                gDestConn = accept(gDestSocket, (struct sockaddr *)&destClientAddr, &destClientAddrLen);
                printf("(%d) Dest connection accepted from %s:%d\n", i, inet_ntoa(destClientAddr.sin_addr), ntohs(destClientAddr.sin_port));
                
                // Only send the packet to dest clients if the packet has been validated
                if (gPacketValidated) SendPacket(buffer, recvlen, gDestConn);
            }
        }
    }

    return 0;
}

#pragma endregion
