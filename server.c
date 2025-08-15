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

int g_packet_count = 0,
    g_socket_count = 0;

bool g_packet_validated,
    g_debug = false;

volatile bool g_loop = true;

// File descriptors for source & dest sockets and connections
int g_source_sock, g_dest_sock;
int g_source_conn, g_dest_conn;

#pragma endregion
#pragma region Server Close

// Closes all of the file descriptors to avoid leaks
void close_fds()
{
    close(g_source_sock);
    close(g_dest_sock);
    close(g_source_conn);
    close(g_dest_conn);
}

// Called when the program receives 'SIGINT'
void handler(int signal)
{
    // Stops the g_loop in main to stop new requests from being accepted
	g_loop = false;

    close_fds();

    printf("\nServer Stopped.\n");
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
 * @param[out] bin_array The binary array representation of the unsigned integer.
 * 
 */
void uint_to_bin_array(uint16_t value, int count, int* bin_array)
{
    uint16_t mask = 1U << (count-1);

    for (int i = 0; i < count; i++)
    {
        bin_array[i] = (value & mask) ? 1 : 0;
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
uint16_t ones_complement_sum(uint16_t a, uint16_t b)
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
void add_socket(int epfd, int fd)
{
    struct epoll_event event;

    event.events = EPOLLIN;
    event.data.fd = fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event);

    g_socket_count++;
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
void process_packet(unsigned char *data, int length)
{
    g_packet_validated = true;

    // Validate the magic byte field
    if (data[0] != MAGIC_BYTE)
    {
        if (g_debug) printf("Magic Byte Error: Received %02x, expecting %02x\n", data[0], MAGIC_BYTE);
        g_packet_validated = false;
    }
    else if (g_debug) printf("Magic Byte Validated (%02x)\n", data[0]);

    // Check the options field for whether the message is sensitive or not
    if (g_packet_validated)
    {
        int digits[8];
        uint_to_bin_array(data[1], 8, digits);

        printf("Options Bit '1' = %d%s\n", digits[1], digits[1] == 1 ? ". Computing and validating checksum..." : "");

        // Validate options padding
        for (int i = 2; i < 8; i++)
        {
            if (digits[i] != PADDING)
            {
                if (g_debug) printf("Options Bit '%d' Padding Error: Received %01x, expecting %01x\n", i, digits[i], PADDING);
                g_packet_validated = false;
                break;
            }
            else if (g_debug) printf("Options Bit '%d' Padding Vaidated (%01x)\n", i, digits[i]);
        }

        if (g_packet_validated && digits[1] == 1)
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
            uint16_t prev_value = 0x00;
            for (int i = 0; i < length; i += 2)
            {
                prev_value = ones_complement_sum(prev_value, (data[i] << 8) + data[i+1]);
            }
            
            // Invert the bits (one's complement)
            uint16_t computed_checksum = ~prev_value;

            // Set the original checksum back
            data[4] = checksum1;
            data[5] = checksum2;

            if (computed_checksum != checksum)
            {
                if (g_debug) printf("Checksum Error: Received %04x, expecting %04x\n", checksum, computed_checksum);
                g_packet_validated = false;
            }
            else if (g_debug) printf("Checksum Validated (%04x)\n", checksum);
        }
    }

    if (g_packet_validated)
    {
        // Validate the padding in the header
        if (data[6] != PADDING || data[7] != PADDING)
        {
            if (g_debug) printf("Padding Error: Received %02x, expecting %02x\n", data[6] != PADDING ? data[6] : data[7], PADDING);
            g_packet_validated = false;
        }
        else if (g_debug) printf("Padding Validated (%02x)\n", data[6] != PADDING ? data[6] : data[7]);
    }

    if (g_packet_validated)
    {
        // Validate data length in the header
        uint16_t data_length = (data[2] << 8) + data[3]; // unsigned + network byte order
        int acc_data_length = length - HEADER_SIZE;

        if (data_length != acc_data_length)
        {
            if (g_debug) printf("Data Length Error: Received %u, expecting %d\n", data_length, acc_data_length);
            g_packet_validated = false;
        }
        else if (g_debug) printf("Data Length Validated (%u)\n", data_length);
    }

    printf(g_packet_validated ? "Packet %d Validated!\n\n" : "Packet %d Not Validated!\n\n", g_packet_count);

    g_packet_count++;
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
void send_packet(unsigned char *data, int length, int client)
{
    ssize_t fs = send(client, data, length, MSG_NOSIGNAL);
    printf("Sent data to: '%d' (%d bytes)\n\n", client, length);

    if (fs == -1) printf("Error: send_packet failed: %s (%d)\n", strerror(errno), errno);
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
void print_packet(unsigned char *data, int length)
{
    printf(" === PACKET %ld HEADER ===\n", g_packet_count);

    for (int i = 0; i < HEADER_SIZE; i++)
    {
        printf("%02x ", data[i]);
    }

    printf("\n === PACKET %ld DATA == \n", g_packet_count);
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
    struct sockaddr_in source_addr, dest_addr, source_client_addr, dest_client_addr;
    socklen_t source_client_addr_len = sizeof(source_client_addr);
    socklen_t dest_client_addr_len = sizeof(dest_client_addr);
    
    // Initialise buffer
    unsigned char buffer[BUFFER_SIZE];
    int recvlen;

    bool debug_print = false;

    // Verifying command-line arguments
    if (argc >= 1 && argc <= 3)
    {
        for (int i = 1; i < argc; i++)
        {
            if (strcmp(argv[i], "-d") == 0) 
            {
                g_debug = true;
                printf("Debug: Packet Validation Information\n");
            }
            else if (strcmp(argv[i], "-p") == 0) 
            {
                debug_print = true;
                printf("Debug: Raw Packet Data\n");
            }
            else
            {
                printf("Error: Invalid command-line argument. Expecting one of '-d', '-p'\n");
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
    if ((g_source_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
		printf("Error: cannot create source socket\n");
		exit(EXIT_FAILURE);
	}
    if ((g_dest_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
		printf("Error: cannot create dest socket\n");
		exit(EXIT_FAILURE);
	}
    
    // Set source address with the source port
    source_addr.sin_family = AF_INET;
    source_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    source_addr.sin_port = htons(SOURCE_PORT);

    // Set dest address with the dest port
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    dest_addr.sin_port = htons(DEST_PORT);

    // Bind source & dest sockets with their respective addresses
    if (bind(g_source_sock, (struct sockaddr *)&source_addr, sizeof(source_addr)) < 0)
    {
		printf("Error: source bind failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
    if (bind(g_dest_sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0)
    {
		printf("Error: dest bind failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

    // Start listening on source & dest sockets
    if (listen(g_source_sock, 0) < 0)
    {
        printf("Error: source listen failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (listen(g_dest_sock, SOMAXCONN) < 0)
    {
        printf("Error: dest listen failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, handler);

    printf("Server Started.\nWaiting on port %d and %d\n\n", SOURCE_PORT, DEST_PORT);

    int epfd = epoll_create1(0);
    if (epfd < 0)
    {
        printf("Error: epoll_create1 failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    add_socket(epfd, g_source_sock);
    add_socket(epfd, g_dest_sock);

    struct epoll_event events[g_socket_count];

    while (g_loop)
    {   
        // Wait for a file descriptor to have new activity (incoming connection)
        int n = epoll_wait(epfd, events, g_socket_count, -1);
        if (n < 0)
        {
            // Ignore the 'Interrupted system call' error when the user initiates it
            if (errno == EINTR) break;

            printf("Error: epoll_wait failed: %s\n", strerror(errno));
            close_fds();
            
            exit(EXIT_FAILURE);
        }

        for (int i = 0; i < n; i++)
        {
            // Check whether the event is EPOLLIN
            bool incoming_conn = events[i].events & EPOLLIN;
            if (!incoming_conn) continue;

            if (events[i].data.fd == g_source_sock) 
            {
                // New source connection (to read from)
                g_source_conn = accept(g_source_sock, (struct sockaddr *)&source_client_addr, &source_client_addr_len);
                printf("Source connection accepted from %s:%d\n", inet_ntoa(source_client_addr.sin_addr), ntohs(source_client_addr.sin_port));
                
                // Read the packet sent
                recvlen = read(g_source_conn, buffer, sizeof(buffer));
                printf("Received packet %d (%d bytes)\n\n", g_packet_count, recvlen);

                if (debug_print) print_packet(buffer, recvlen);
                process_packet(buffer, recvlen);
            }
            else if (events[i].data.fd == g_dest_sock)
            {
                // New dest connection (to write to)
                g_dest_conn = accept(g_dest_sock, (struct sockaddr *)&dest_client_addr, &dest_client_addr_len);
                printf("Dest connection accepted from %s:%d\n", inet_ntoa(dest_client_addr.sin_addr), ntohs(dest_client_addr.sin_port));
                
                // Only send the packet to dest clients if the packet has been validated
                if (g_packet_validated) send_packet(buffer, recvlen, g_dest_conn);
            }
        }
    }

    return 0;
}

#pragma endregion
