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
#define MAX 100
#define SA struct sockaddr 

void sentFile(int sockfd) 
{ 
	char buff[MAX]; 						// for read operation from file and used to sent operation 
	
	// create file 
	FILE *fp=fopen("myconfig.json","r");	// open file uses both stdio and stdin header files
											// file should be present at the program directory

	if( fp == NULL ){
		printf("Error IN Opening File .. \n");
		return ;
	}
	
	while ( fgets(buff,MAX,fp) != NULL )	// fgets reads upto MAX character or EOF 
		write(sockfd,buff,sizeof(buff)); 	// sent the file data to stream
	
	fclose (fp);							// close the file 
	
	printf("File Sent successfully !!! \n");
	
} 

int main(int argc, char *argv[]) 
{ 
	int sockfd, connfd; 
	struct sockaddr_in serv_addr, cli; 

	// socket create and varification 
	sockfd = socket(AF_INET, SOCK_STREAM, 0); 
	if (sockfd == -1) { 
		printf("socket creation failed...\n"); 
		exit(0); 
	} 
	else
		printf("Socket successfully created..\n"); 
	
	bzero(&serv_addr, sizeof(serv_addr)); 

	// assign IP, PORT 
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr("10.0.0.249");
	serv_addr.sin_port = htons(8765);

	// connect the client socket to server socket 
	if (connect(sockfd, (SA*)&serv_addr, sizeof(serv_addr)) != 0) { 
		printf("connection with the server failed...\n"); 
		exit(0); 
	} 
	else
		printf("connected to the server..\n"); 
	FILE *fp = fopen(argv[1], "r");

	// function for sending File 
	recvFile(sockfd); 

	// close the socket 
	close(sockfd); 
} 