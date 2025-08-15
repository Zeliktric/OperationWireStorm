CC = gcc

server: server.o 
	$(CC) -o server server.c

clean:
	rm -f server server.o
