#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <json-c/json.h>

void recvFile(int sockfd) 
{ 
	char buff[MAX]; 	// to store message from client
	
	FILE *fp;
	FILE *fp = fopen(argv[1], "w"); // stores the file content in recieved.txt in the program directory
	
	if( fp == NULL ){
		printf("Error IN Opening File ");
		return ;
	}
	
	while( read(sockfd,buff,MAX) > 0 )
		fprintf(fp,"%s",buff);
	
	printf("File received successfully !! \n");
	printf("New File created is received.txt !! \n");

} 

int main(int argc, char *argv[])  
{ 
	int sockfd, connfd, len; 				// create socket file descriptor 
	struct sockaddr_in serv_addr, cli; 		// create structure object of sockaddr_in for client and server

	// socket create and verification 
	sockfd = socket(AF_INET, SOCK_STREAM, 0); 			// creating a TCP socket ( SOCK_STREAM )
	
	if (sockfd == -1) { 
		printf("socket creation failed...\n"); 
		exit(0); 
	} 
	else
		printf("Socket successfully created..\n"); 
	
	// empty the 
	bzero(&serv_addr, sizeof(serv_addr)); 

	// assign IP, PORT 
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr("10.0.0.249");
	serv_addr.sin_port = htons(8765);

	// Binding newly created socket to given IP and verification 
	if ((bind(sockfd, (SA*)&serv_addr, sizeof(serv_addr))) != 0) { 
		printf("socket bind failed...\n"); 
		exit(0); 
	} 
	else
		printf("Socket successfully binded..\n"); 

	// Now server is ready to listen and verification 
	if ((listen(sockfd, 5)) != 0) { 
		printf("Listen failed...\n"); 
		exit(0); 
	} 
	else
		printf("Server listening..\n"); 
	
	len = sizeof(cli); 

	// Accept the data packet from client and verification 
	connfd = accept(sockfd, (SA*)&cli, &len); 	// accepts connection from socket
	
	if (connfd < 0) { 
		printf("server acccept failed...\n"); 
		exit(0); 
	} 
	else
		printf("server acccept the client...\n"); 

	// Function for chatting between client and server 
	sentFile(connfd); 

	// After transfer close the socket 
	close(sockfd); 
} 