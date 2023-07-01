/*
 * doctor1.c
 *
 *  Created on: Nov 25, 2014
 *      Author: Nikita Ahuja
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <pthread.h>
#include <sys/mman.h>

#include "publics.h"
#define DOC1_UDP_STATIC_PORT		"41338"
#define MAXBUFLEN 256

struct insurance_detail{
	char insurance[50];
	char amount[10];
};

struct insurance_detail ins_record[3];

void *get_in_addr(struct sockaddr *sa) {
	return sa->sa_family == AF_INET
			? (void *) &(((struct sockaddr_in*)sa)->sin_addr)
					: (void *) &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/*loading the contents of doc1.txt into insurance structure*/
int load_ins_record(){
	FILE *fp;
	char buf[256];

	/* opening file for reading */
	fp = fopen("doc1.txt", "r");
	if(fp == NULL){
		perror("Error opening file\n");
		return -1;
	}

	int i = 0;
	const char ch[3] = " \n";
	char *token;

	/*code extracted from "Some Hints" discussion pdf*/
	while(fgets (buf, 256, fp)!=NULL && i < 3) {
		char temp_buf[256];
		strcpy(temp_buf, buf);
		token = NULL;

		// get the first token
		token = strtok(temp_buf, ch);
		strcpy(ins_record[i].insurance, token);
		token = strtok(0, ch);
		strcpy(ins_record[i].amount, token);
		i++;
	}
	fclose(fp);
}

int main(){

	/*code extracted from beej guide*/
	int status, sockfd = 0;
	struct addrinfo hints;
	struct addrinfo *res, *p; // will point to the results
	const char *addr = US_SERVER_HOST;

	char s[INET6_ADDRSTRLEN];
	int new_fd = 0;
	struct sockaddr_storage their_addr;
	socklen_t addr_len;
	int retVal;
	char buf[256];
	int numbytes;

	memset(&hints, 0, sizeof hints); // make sure the struct is empty

	hints.ai_family = AF_UNSPEC; // don't care IPv4 or IPv6
	hints.ai_socktype = SOCK_DGRAM; // UDP sockets
	hints.ai_flags = AI_PASSIVE; // fill in my IP for me

	if ((status = getaddrinfo(addr, DOC1_UDP_STATIC_PORT, &hints, &res)) != 0) {
		fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
		exit(1);
	}

	/*code extracted from beej guide*/
	p = res;
	void *server_addr;
	struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
	server_addr = &(ipv4->sin_addr);

	/*convert the IP to a string and print it:*/
	inet_ntop(p->ai_family, server_addr, s, sizeof s);
	printf("\nPhase 3: Doctor 1 has a static UDP port %s and IP address %s.\n", DOC1_UDP_STATIC_PORT, s);

	/*loop through all the results and bind to the first we can*/
	for(p = res; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			perror("socket");
			continue;
		}
		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("bind");
			continue;
		}
		break;  	/*if we get here, we must have connected successfully*/
	}
	if (p == NULL) {
		/*looped off the end of the list with no successful bind*/
		fprintf(stderr, "failed to bind socket\n");
		exit(2);
	}

	freeaddrinfo(res); 		/*free the linked-list*/

	if((retVal = load_ins_record()) < 0)
		return retVal;

	while(1){

		addr_len = sizeof their_addr;
		if ((numbytes = recvfrom(sockfd, buf, MAXBUFLEN-1 , 0, (struct sockaddr *)&their_addr, &addr_len)) == -1)
		{
			perror("Doctor1 Error: recvfrom");
			exit(1);
		}
		buf[numbytes] = '\0';
		inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), s, sizeof s);

		int port = ntohs(((struct sockaddr_in *)&their_addr)->sin_port);

		printf("\nPhase 3: Doctor 1 receives the request from the patient with port number %d and name _____ with the insurance plan %s.\n", port, buf);
		
		
		char sendBuf[256];
		int i;
		for(i = 0; i<3; i++){
			if(strcmp(buf, ins_record[i].insurance) == 0){
				strcpy(sendBuf, ins_record[i].amount);
				break;
			}
		}

		if ((numbytes = sendto(sockfd, sendBuf, strlen(sendBuf) , 0, (struct sockaddr *)&their_addr, addr_len)) == -1)
		{
			perror("Doctor1 Error: recvfrom");
			exit(1);
		}
		printf("\nPhase 3: Doctor 1 has sent estimated price %s$ to patient with port number %d.\n", sendBuf, port);
	}

	close(sockfd);
	return 0;
}
