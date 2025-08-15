# Operation WIRE STORM - RELOADED Submission

## Prerequisites
Download `gcc`:
```
$  sudo apt install gcc
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

To run the server, enter:
```
$ ./server
```
The server can also be started using any of the below optional flags for debugging & verification information:
```
$ ./server -d
```
Packet validation information are output.
```
$ ./server -p
```
Raw packet data is output.

where packet validation successes will also be output to the terminal.

## Verification
Details of:
- Source client connection
- Destination client connections
- Reading of packets from the source socket
- Sending of packets to client connections
- Major errors

are automatically output to the terminal.
