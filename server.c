#include <stdio.h>
#include <stdlib.h>
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

#pragma endregion
#pragma region Global Variables

int packetCount = 0,
    packetValidated = 1,
    debug = 0; // Whether extra info such as packet validation error messages and raw packet printing should be output or not
volatile int loop = 1;

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
	loop = 0;

    CloseFds();

    printf("\nServer stopped.\n");
}

#pragma endregion
#pragma region Process Packet

/**
 * Determines whether a packet is valid or not by the given rules:
 * 1) Magic byte must be correct
 * 2) Data length must match actual length of the data
 * 3) Header format is correct
 * 
 * @param[in] data The pointer to the packet that was read from the source socket.
 * @param[in] length The length (in bytes) of the packet.
 */
void ProcessPacket(unsigned char *data, int length)
{
    packetValidated = 1;

    // Validate the magic byte field
    if (data[0] != MAGIC_BYTE)
    {
        if (debug == 1) printf("Magic Byte Error. Received %02x, expecting %02x\n", data[0], MAGIC_BYTE);
        packetValidated = 0;
    }

    if (packetValidated == 1)
    {
        // Validate the padding in the header
        for (int i = 1; i < HEADER_SIZE; i++)
        {
            // Data length field, skip for now
            if (i == 2 || i == 3) continue;

            if ((i == 1 || i > 3 && i < 8) && data[i] != PADDING)
            {
                if (debug == 1) printf("Padding Error. Received %02x, expecting %02x\n", data[i], PADDING);
                packetValidated = 0;
                break;
            }
            
            // Stop the loop if the packet is not valid
            if (packetValidated == 0) break;
        }
    }

    if (packetValidated == 1)
    {
        // Validate data length in the header
        uint16_t data_length = (data[2] << 8) + data[3]; // unsigned + network byte order
        int acc_data_length = length - HEADER_SIZE;

        if (data_length != acc_data_length)
        {
            if (debug == 1) printf("Data Length Error. Received %u, expecting %d\n", data_length, acc_data_length);
            packetValidated = 0;
        }
    }

    printf(packetValidated == 1 ? "Packet %d validated!\n\n" : "Packet %d not validated!\n\n", packetCount);

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
 * Utility/Debugging method for printing raw packet data
 * Adapted from: University coursework
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
            debug = 1;
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

                    if (debug == 1) PrintPacket(buffer, recvlen);
                    ProcessPacket(buffer, recvlen);
                }
                else if (i == destSocket)
                {
                    // New dest connection (to write to)
                    destConn = accept(destSocket, (struct sockaddr *)&destClientAddr, &destClientAddrLen);
                    printf("Dest connection accepted from %s:%d\n", inet_ntoa(destClientAddr.sin_addr), ntohs(destClientAddr.sin_port));
                    
                    // Only send the packet to dest clients if the packet has been validated
                    if (packetValidated == 1) SendPacket(buffer, recvlen, destConn);
                }
            }
        }
    }

    return 0;
}

#pragma endregion