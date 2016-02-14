/*
 * patient2.c
 *
 *  Created on: Nov 11, 2014
 *  Author: Nikita Ahuja
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

#define HCS_TCP_STATIC_PORT		"21338"
#define MY_USCID	338

#define BACKLOG 10
#define MAXBUFLEN 256

char username[256];
char password[256];

char doc[10];
char doc_port[10];

void *get_in_addr(struct sockaddr *sa) {
	return sa->sa_family == AF_INET
			? (void *) &(((struct sockaddr_in*)sa)->sin_addr)
					: (void *) &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/*fetching the contents of patient2.txt*/
int load_credentials(){
	/*code extracted from "Some Hints" discussion pdf*/
	FILE *fp;
	char buf[256];

	/* opening file for reading */
	fp = fopen("patient2.txt", "r");
	if(fp == NULL){
		perror("Error opening file\n");
		return -1;
	}

	const char s[3] = " \n";
	char *token;

	/*code extracted from "Some Hints" discussion pdf*/
	fgets (buf, 256, fp);
	token = NULL;
	/* get the first token */
	token = strtok(buf, s);
	strcpy(username, token);
	/* walk through other tokens */
	token = strtok(0, s);
	strcpy(password, token);
	fclose(fp);
}

/*select the index option entered by patient2*/
void select_choice(char buf[], char choice[2]){
	const char s[2] = "\n";
	char *token;

	while(1){
		char temp_buf[1024];
		strcpy(temp_buf,buf);
		int i = 0;

		printf("\nPlease enter the preferred appointment index and press enter: ");
		scanf("%s", choice);

		if(isdigit(choice[0]) && !isdigit(choice[1])){
			token = strtok(temp_buf, s);
			while(token != NULL){
				if(token[0] == choice[0])
					goto done;
				token = strtok(0, s);
			}
		}
		strcpy(choice, "");
	}

	done:
	return;
}

int phase1_2(){

	int retVal;
	if((retVal = load_credentials()) < 0)
		return retVal;

	/*code extracted from beej guide*/
	int sockfd;
	struct addrinfo hints, *servinfo, *p;
	int rv;
	const char *addr = "nunki.usc.edu";

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;  /*use AF_INET6 to force IPv6*/
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(addr, HCS_TCP_STATIC_PORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		exit(1);
	}

	/*loop through all the results and connect to the first we can*/
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			perror("socket");
			continue;
		}
		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("connect");
			continue;
		}
		break; /*if we get here, we must have connected successfully*/
	}

	if (p == NULL) {
		/*looped off the end of the list with no connection*/
		fprintf(stderr, "failed to connect\n");
		exit(2);
	}

	/*code extracted from beej guide*/
	struct sockaddr_in sin;
	socklen_t addrlen;
	int getsock_check;
	char s[INET6_ADDRSTRLEN];

	addrlen = sizeof(sin);
	getsock_check = getsockname(sockfd,(struct sockaddr *) &sin, &addrlen);
	if (getsock_check == -1) {
		perror("Patient2 error: getsockname");
		exit(1);
	}

	p = servinfo;
	void *server_addr;
	struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
	server_addr = &(ipv4->sin_addr);

	// convert the IP to a string and print it:
	inet_ntop(p->ai_family, server_addr, s, sizeof s);

	printf("\nPhase 1: Patient 1 has TCP port number %d and IP address %s.\n",ntohs(sin.sin_port),s);

	freeaddrinfo(servinfo); // all done with this structure

	/*==============================================================*/

	char sendBuf[1024];
	memset(sendBuf, '0' ,sizeof(sendBuf));

	strcpy(sendBuf, "authenticate ");
	strcat(sendBuf, username);
	strcat(sendBuf, " ");
	strcat(sendBuf, password);

	if (send(sockfd, sendBuf, strlen(sendBuf), 0) == -1)
	{
		perror("Patient2 Error: while sending\n");
		exit(1);
	}

	printf("\nPhase 1: Authentication request from Patient 1 with username %s and password %s has been sent to the Health Center Server.\n", username, password);

	int number_of_bytes;
	char recvBuf[256];
	memset(recvBuf, '0' ,sizeof(recvBuf));

	if ((number_of_bytes = recv(sockfd, recvBuf, MAXBUFLEN-1, 0)) == -1)
	{
		perror("Patient2 Error: when receiving bytes\n");
		exit(1);
	}

	recvBuf[number_of_bytes] = '\0';

	printf("\nPhase 1: Patient 1 authentication result: %s.\n", recvBuf);

	printf("\nPhase 1: End of Phase 1 for Patient2.\n");

	if(strcmp(recvBuf, "success") == 0){

		/*start of phase2 stage1*/
		if (send(sockfd, "available", 9, 0) == -1)
		{
			perror("Patient2 Error: while sending\n");
			exit(1);
		}

		memset(recvBuf, '0' ,sizeof(recvBuf));
		if ((number_of_bytes = recv(sockfd, recvBuf, MAXBUFLEN-1, 0)) == -1)
		{
			perror("Patient2 Error: when receiving bytes\n");
			exit(1);
		}
		recvBuf[number_of_bytes] = '\0';
		printf("\nPhase 2: The following appointments are available for Patient 1:\n");
		fputs(recvBuf, stdout);

		char ch[2];
		memset(ch, '\0' ,sizeof(ch));
		select_choice(recvBuf, ch);

		memset(sendBuf, '\0' ,sizeof(sendBuf));
		strcpy(sendBuf,"selection ");
		strcat(sendBuf, ch);

		if (send(sockfd, sendBuf, strlen(sendBuf), 0) == -1)
		{
			perror("Patient2 Error: while sending\n");
			exit(1);
		}
		/*end of phase2 stage1*/

		/*start of phase2 stage2*/
		memset(recvBuf, '\0' ,sizeof(recvBuf));
		if ((number_of_bytes = recv(sockfd, recvBuf, MAXBUFLEN-1, 0)) == -1)
		{
			perror("Patient2 Error: when receiving bytes\n");
			exit(1);
		}
		recvBuf[number_of_bytes] = '\0';

		if(strcmp(recvBuf, "notavailable") == 0){
			printf("\nPhase 2: The requested appointment from Patient 1 is not available. Exiting…\n");
			close(sockfd);
			exit(0);
		}

		const char s[2] = " ";
		char *token;
		token = strtok(recvBuf, s);
		strcpy(doc, token);
		token = strtok(0, s);
		strcpy(doc_port, token);

		printf("\nPhase 2: The requested appointment is available and reserved to Patient2. The assigned doctor port number is %s.\n", doc_port);
		close(sockfd);
		return 1;
	}
	else if(strcmp(recvBuf, "failure") == 0){
		close(sockfd);
		exit(1);
	}

	close(sockfd);
	return 0;
}

int phase3(){
	FILE *fp;
	char buf[256];
	char insurance[50];

	memset(insurance, '\0' ,sizeof(insurance));
	/* opening file for reading */
	fp = fopen("patient2insurance.txt", "r");
	if(fp == NULL){
		perror("Error opening file\n");
		return -1;
	}

	char *token;
	/*code extracted from "Some Hints" discussion pdf*/
	fgets (buf, 256, fp);
	token = NULL;
	/* get the first token */
	token = strtok(buf, "\n");
	strcpy(insurance, token);
	fclose(fp);

	/*code extracted from beej guide*/
	int sockfd;
	struct addrinfo hints, *servinfo, *p;
	int rv;
	const char *addr = "nunki.usc.edu";

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;  /*use AF_INET6 to force IPv6*/
	hints.ai_socktype = SOCK_DGRAM;

	int port = atoi(doc_port) + MY_USCID;
	char doc_udp_port[10];
	memset(doc_udp_port, '\0' ,sizeof(doc_udp_port));
	sprintf(doc_udp_port, "%d", port);

	if ((rv = getaddrinfo(addr, doc_udp_port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		exit(1);
	}
	/*loop through all the results and connect to the first we can*/
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			perror("socket");
			continue;
		}
		break; 	/*if we get here, we must have connected successfully*/
	}

	if (p == NULL) {
		/*looped off the end of the list with no connection*/
		fprintf(stderr, "failed\n");
		exit(2);
	}
	/*code extracted from beej guide*/
	struct sockaddr_in sin;
	socklen_t addrlen;
	int getsock_check;
	char s[INET6_ADDRSTRLEN];
	int numbytes;
	struct sockaddr_storage their_addr;
	socklen_t addr_len;

	addrlen = sizeof(sin);
	getsock_check = getsockname(sockfd,(struct sockaddr *) &sin, &addrlen);
	if (getsock_check == -1) {
		perror("Patient2 error: getsockname");
		exit(1);
	}

	void *server_addr;
	struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
	server_addr = &(ipv4->sin_addr);

	// convert the IP to a string and print it:
	/*inet_ntop(p->ai_family, server_addr, s, sizeof s);
	inet_ntop(servinfo->ai_family, get_in_addr((struct sockaddr *)servinfo->ai_addr), s, sizeof s);
	getsockname(sockfd,(struct sockaddr *) &sin, &addrlen);
	*/

	inet_ntop(servinfo->ai_family, get_in_addr((struct sockaddr *)servinfo->ai_addr), s, sizeof s);

	/*check*/
	printf("\nPhase 3: Patient 1 has a dynamic UDP port number %d and IP address %s.\n", (int)ntohs(sin.sin_port),s);

	/*code extracted from beej guide*/
	if ((numbytes = sendto(sockfd, insurance, strlen(insurance), 0, p->ai_addr, p->ai_addrlen)) == -1) {
		perror("Patient2 error: sendto");
		exit(1);
	}

	/*check : remove "port" as its unnecessary. use doc_udp_port instead*/
	port = ntohs(((struct sockaddr_in *)p->ai_addr)->sin_port);

	printf("\nPhase 3: The cost estimation request from Patient 1 with insurance plan %s has been sent to the doctor with port number %d and IP address %s.\n", insurance, port, s);

	/*check*/
 	/*printf("\nPhase 3: The cost estimation request from Patient 1 with insurance plan %s has been sent to the doctor with port number %s and IP address %s.\n", insurance, doc_udp_port, s);*/

	addr_len = sizeof their_addr;
	if ((numbytes = recvfrom(sockfd, buf, MAXBUFLEN-1 , 0, (struct sockaddr *)&their_addr, &addr_len)) == -1)
	{
		perror("Patient2 Error: recvfrom");
		exit(1);
	}
	buf[numbytes] = '\0';

	/*check : remove "port" as its unnecessary. use doc_udp_port instead*/
	port = ntohs(((struct sockaddr_in *)&their_addr)->sin_port);
	printf("\nPhase 3: Patient 1 receives %s$ estimation cost from doctor with port number %d and name %s.\n", buf, port, doc);
	printf("\nPhase 3: End of Phase 3 for Patient 1.\n");
	freeaddrinfo(servinfo);  	/*all done with this structure*/
	close(sockfd);
	return 1;
}

int main(void)
{
	int retVal = 0;
	if(( retVal = phase1_2()) != 1)
		return retVal;

	if(( retVal = phase3()) != 1)
		return retVal;

	return 0;
}
