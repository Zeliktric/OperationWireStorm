# Operation WIRE STORM - RELOADED Submission

[Final commit for task 1](https://github.com/Zeliktric/OperationWireStorm/commit/5a29ba77cefb53d826bf59b06bdebce16db38dfc)

## Prerequisites
Download `gcc`:
```
$ sudo apt install gcc
```
Download `make`:
```
$ sudo apt install make
```

## Build
To build and compile the server, enter:
```
$ make
```

## Run
To run the server, enter:
```
$ ./server
```
The server can also be started using any of the below optional flags for debugging & verification information.

**Information about the packet validation process is output:**
```
$ ./server -d
```
**The raw packet is output (header + packet data):**
```
$ ./server -p
```
**Both flags can be used:**
```
$ ./server -d -p
```

## Verification
Details of:
- Source client connection
- Destination client connections
- Reading of packets from the source socket
- Sending of packets to client connections
- Major errors

are automatically output to the terminal.

Tested and verified (all tests passed) on Ubuntu 24.04.
