CC = gcc

all: server

server: server.o 
	$(CC) -o server server.o 

server.o: server.c

clean:
	rm -f server server.o 
