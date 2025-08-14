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
#include <sys/select.h>
#include <sys/types.h>
#include <signal.h>

#pragma region Macros

#define BUFFER_SIZE 256000
#define SOURCE_PORT 33333
#define DEST_PORT 44444

#define MAGIC_BYTE 0xCC
#define HEADER_SIZE 8
#define PADDING 0x00
#define BINARY_LEN 8

#pragma endregion
#pragma region Global Variables

int packetCount = 0;
bool packetValidated = true,
    debug = false; // Whether extra info such as packet validation error messages and raw packet printing should be output or not
volatile bool loop = true;

// File descriptors for source & dest sockets and connections
int sourceSocket, destSocket;
int sourceConn, destConn;

#pragma endregion
#pragma region Server Close

// Closes all of the file descriptors to avoid leaks
void CloseFds()
{
    close(sourceSocket);
    close(destSocket);
    close(sourceConn);
    close(destConn);
}

// Called when the program receives 'SIGINT'
void Handler(int signal)
{
    // Stops the loop in main to stop new requests from being accepted
	loop = false;

    CloseFds();

    printf("\nServer stopped.\n");
}

#pragma endregion
#pragma region Process Packet

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
void UIntToBinArray(unsigned int value, int count, int* binArray)
{
    unsigned int mask = 1U << (count-1);

    for (int i = 0; i < count; i++)
    {
        binArray[i] = (value & mask) ? 1 : 0;
        value <<= 1;
    }
}

/**
 * Utility function to add two numbers together in one's complement.
 * 
 * Adapted from: https://stackoverflow.com/a/67358741
 * 
 * @param[in] a The first number in the addition.
 * @param[in] b The second number in the addition.
 */
uint16_t OnesComplementSum(uint16_t a, uint16_t b)
{
    uint32_t sum = a + b;
    return (sum & 0xFFFF) + (sum >> 16);
}

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
    packetValidated = true;

    // Validate the magic byte field
    if (data[0] != MAGIC_BYTE)
    {
        if (debug) printf("Magic Byte Error. Received %02x, expecting %02x\n", data[0], MAGIC_BYTE);
        packetValidated = false;
    }

    // Check the options field for whether the message is sensitive or not
    if (packetValidated)
    {
        int digits[8];
        UIntToBinArray(data[1], 8, digits);

        // Validate options padding
        for (int i = 2; i < 8; i++)
        {
            if (digits[i] != PADDING)
            {
                if (debug) printf("Padding Error. Received %02x, expecting %02x\n", digits[i], PADDING);
                packetValidated = false;
                break;
            }
        }

        if (packetValidated && digits[1] == 1)
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
                if (debug) printf("Checksum Error. Received %04x, expecting %04x\n", checksum, computedChecksum);
                packetValidated = false;
            }
        }
    }

    if (packetValidated)
    {
        // Validate the padding in the header
        if (data[6] != PADDING || data[7] != PADDING)
        {
            if (debug) printf("Padding Error. Received %02x, expecting %02x\n", data[6] != PADDING ? data[6] : data[7], PADDING);
            packetValidated = false;
        }
    }

    if (packetValidated)
    {
        // Validate data length in the header
        uint16_t data_length = (data[2] << 8) + data[3]; // unsigned + network byte order
        int acc_data_length = length - HEADER_SIZE;

        if (data_length != acc_data_length)
        {
            if (debug) printf("Data Length Error. Received %u, expecting %d\n", data_length, acc_data_length);
            packetValidated = false;
        }
    }

    printf(packetValidated ? "Packet %d validated!\n\n" : "Packet %d not validated!\n\n", packetCount);

    packetCount++;
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
void PrintPacket(const unsigned char *data, int length)
{
    printf("\n === PACKET %ld HEADER ===\n", packetCount);

    for (int i = 0; i < HEADER_SIZE; i++)
    {
        printf("%02x ", data[i]);
    }

    printf("\n === PACKET %ld DATA == \n", packetCount);
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
    
    unsigned char buffer[BUFFER_SIZE];
    int recvlen;

    // Verifying command-line arguments
    if (argc > 2)
    {
        printf("Error: too many command-line arguments\n");
        exit(EXIT_FAILURE);
    }
    else if (argc == 2)
    {
        if (strcmp(argv[1], "-d") == 0) 
        {
            debug = true;
            printf("Debug: ON\n");
        }
        else
        {
            printf("Error: invalid command-line argument. Expecting '-d'\n");
            exit(EXIT_FAILURE);
        }
    }

    // Create source & dest sockets
    if ((sourceSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
		printf("Error: cannot create source socket\n");
		exit(EXIT_FAILURE);
	}
    if ((destSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
		printf("Error: cannot create dest socket\n");
		exit(EXIT_FAILURE);
	}

    sourceAddr.sin_family = AF_INET;
    sourceAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    sourceAddr.sin_port = htons(SOURCE_PORT);

    destAddr.sin_family = AF_INET;
    destAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    destAddr.sin_port = htons(DEST_PORT);

    // Bind source & dest sockets with their respective addresses
    if (bind(sourceSocket, (struct sockaddr *)&sourceAddr, sizeof(sourceAddr)) < 0)
    {
		printf("Error: source bind failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
    if (bind(destSocket, (struct sockaddr *)&destAddr, sizeof(destAddr)) < 0)
    {
		printf("Error: dest bind failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

    // Start listening on source & dest sockets
    if (listen(sourceSocket, 0) < 0)
    {
        printf("Error: source listen failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (listen(destSocket, SOMAXCONN) < 0)
    {
        printf("Error: dest listen failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, Handler);

    printf("Server started.\nWaiting on port %d and %d\n\n", SOURCE_PORT, DEST_PORT);

    // Adapted from: https://www.gnu.org/software/libc/manual/html_node/Server-Example.html
    fd_set active_fd_set, read_fd_set;
    FD_ZERO(&active_fd_set);
    FD_SET(sourceSocket, &active_fd_set);
    FD_SET(destSocket, &active_fd_set);

    while (loop)
    {
        read_fd_set = active_fd_set;
        // Select the file descriptor that has new activity
        if (select(FD_SETSIZE, &read_fd_set, NULL, NULL, NULL) < 0)
        {
            // Ignore the 'Interrupted system call' error when the user initiates it
            if (errno == EINTR) break;

            printf("Error: select failed: %s\n", strerror(errno));
            CloseFds();
            
            exit(EXIT_FAILURE);
        }

        for (int i = 1; i < FD_SETSIZE; i++)
        {
            if (FD_ISSET(i, &read_fd_set))
            {
                if (i == sourceSocket)
                {
                    // New source connection (to read from)
                    sourceConn = accept(sourceSocket, (struct sockaddr *)&sourceClientAddr, &sourceClientAddrLen);
                    printf("Source connection accepted from %s:%d\n", inet_ntoa(sourceClientAddr.sin_addr), ntohs(sourceClientAddr.sin_port));
                    
                    // Read the packet sent
                    recvlen = read(sourceConn, buffer, sizeof(buffer));
                    printf("Received packet %d (%d bytes)\n", packetCount, recvlen);

                    if (debug) PrintPacket(buffer, recvlen);
                    ProcessPacket(buffer, recvlen);
                }
                else if (i == destSocket)
                {
                    // New dest connection (to write to)
                    destConn = accept(destSocket, (struct sockaddr *)&destClientAddr, &destClientAddrLen);
                    printf("Dest connection accepted from %s:%d\n", inet_ntoa(destClientAddr.sin_addr), ntohs(destClientAddr.sin_port));
                    
                    // Only send the packet to dest clients if the packet has been validated
                    if (packetValidated) SendPacket(buffer, recvlen, destConn);
                }
            }
        }
    }

    return 0;
}

#pragma endregion
