# Operation WIRE STORM Submission

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

The server can also be started in "debug" mode:
```
$ ./server -d
```
where raw packet data and packet validation errors will be output to the terminal.

## Verification
Details of:
- Source client connection
- Destination client connections
- Reading of packets from the source socket
- Sending of packets to client connections
- Major errors  
are automatically output to the terminal.
