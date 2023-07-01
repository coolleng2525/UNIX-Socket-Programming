/*
 * healthcenterserver.c
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
#include <pthread.h>
#include <sys/mman.h>

#include "publics.h"

#define HCS_TCP_STATIC_PORT		"21338"
#define BACKLOG 10
#define MAXBUFLEN 256

struct users {
	char username[256];
	char password[256];
};

struct availabilities {
	char time_slot[256];
	int reserved;
};

int total_availabilities = 0;

static pthread_mutex_t *m;

struct users patient[2];

typedef struct availabilities_tag{
	struct availabilities appointment[6];
}AVAILABILITIES ;

/*shared pointer needed since fork is used*/
static AVAILABILITIES *av;

void *get_in_addr(struct sockaddr *sa) {
	return sa->sa_family == AF_INET
			? (void *) &(((struct sockaddr_in*)sa)->sin_addr)
					: (void *) &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void sigchld_handler(int s)
{
	while(waitpid(-1, NULL, WNOHANG) > 0);
}

/*check if the credentials received match any of the patient details*/
int check_authentication(char *buf, struct users *temp){
	const char s[2] = " ";
	char *token;

	char temp_buf[256];
	strcpy(temp_buf, buf); 
	/* get the first token */
	token = strtok(temp_buf, s);

	if(strcmp(token, "authenticate") != 0)
		return 0;

	token = strtok(0, s);
	int i;
	for(i=0; i<2; i++){
		if(strcmp(token, patient[i].username) == 0){
			strcpy(temp->username, token);
			token = strtok(0, s);
			if(strcmp(token, patient[i].password) == 0){
				strcpy(temp->password, token);
				return 1;
			}
		}
	}
	return 0;
}

/*fetch the contents of file users.txt and load it into patient structure*/
int create_users(){

	/*code extracted from "Some Hints" discussion pdf*/
	FILE *fp;
	char buf[256];

	/* opening file for reading */
	fp = fopen(USER_FILE, "r");
	if(fp == NULL){
		perror("Error opening file\n");
		return -1;
	}

	int i = 0;
	const char ch[3] = " \n";
	char *token;

	/*code extracted from "Some Hints" discussion pdf*/
	while(fgets (buf, 256, fp)!=NULL && i < 2) {
		char temp_buf[256];
		strcpy(temp_buf, buf);
		token = NULL;

		/* get the first token */
		token = strtok(temp_buf, ch);
		strcpy(patient[i].username, token);

		/* walk through other tokens */
		token = strtok(0, ch);
		strcpy(patient[i].password, token);
		i++;
	}
	fclose(fp);
}

/*fethcing the contents of availabilities.txt file and loading it onto AVAILABILITIES structure*/
int create_availabilities(){

	FILE *fp;
	char buf[256];

	/* opening file for reading */
	fp = fopen("availabilities.txt", "r");
	if(fp == NULL){
		perror("Error opening file\n");
		return -1;
	}

	int i = 0;
	const char ch[2] = "\n";
	char *token;

	/*code extracted from "Some Hints" discussion pdf*/
	while(fgets (buf, 256, fp)!=NULL && i < 6) {
		//while(fscanf(fp, "%s\n", buf) != 0){
		char temp_buf[256];
		strcpy(temp_buf, buf);
		token = NULL;

		// get the first token
		token = strtok(temp_buf, ch);
		pthread_mutex_lock(m);
		strcpy(av->appointment[i].time_slot, buf);
		av->appointment[i].reserved = 0;
		pthread_mutex_unlock(m);
		i++;
	}
	total_availabilities = i;
	fclose(fp);
}

/*check if the appointment selected is reserved*/
int check_availability(char buf[], char sendBuf[]){
	const char s[3] = " \n";
	char *token;

	token = strtok(buf, s);
	token = strtok(0, s);

	int i;
	for(i = 0; i < total_availabilities; i++){
		pthread_mutex_lock(m);
		if(token[0] == av->appointment[i].time_slot[0]){
			if(av->appointment[i].reserved == 0){
				av->appointment[i].reserved = 1;
				strcpy(sendBuf, (av->appointment[i].time_slot+11));
				return 1;
			}
			else
				return 0;
		}
		pthread_mutex_unlock(m);
	}
	return 0;
}

int phase2(int *sockfd, int *port, char *ip){

	char buf[1024];
	int number_of_bytes;
	memset(buf, '0' ,sizeof(buf));
	if ((number_of_bytes = recv(*sockfd, buf, MAXBUFLEN-1, 0)) == -1)
	{
		perror("Healthcenterserver Error: when receiving bytes\n");
		exit(1);
	}
	buf[number_of_bytes] = '\0';

	if(strcmp(buf, "available") != 0){
		close(*sockfd);
		exit(0);
	}

	printf("\nPhase 2: The Health Center Server, receives a request for available time slots from patients with port number %d and IP address %s.\n", *port, ip);

	memset(buf, '\0' ,sizeof(buf));
	strcpy(buf, "");
	int i;
	for(i = 0; i < total_availabilities; i++){
		pthread_mutex_lock(m);
		if(av->appointment[i].reserved == 0){
			strncat(buf, av->appointment[i].time_slot, 10);
			strcat(buf, "\n");
		}
		pthread_mutex_unlock(m);
	}

	if (send(*sockfd, buf, strlen(buf), 0) == -1)
	{
		perror("Healthcenterserver Error: while sending\n");
		exit(1);
	}
	return 1;
}

int phase1(){

	/*code extracted from beej guide*/
	int status, sockfd = 0;
	struct addrinfo hints;
	struct addrinfo *res, *p; // will point to the results
	const char *addr = US_SERVER_HOST;
	char s[INET6_ADDRSTRLEN];
	int new_fd = 0;
	struct sockaddr_storage their_addr;
	socklen_t sin_size;
	struct sigaction sa;
	int retVal;
	char buf[256];

	memset(&hints, 0, sizeof hints); // make sure the struct is empty

	hints.ai_family = AF_UNSPEC; // don't care IPv4 or IPv6
	hints.ai_socktype = SOCK_STREAM; // TCP stream sockets
	hints.ai_flags = AI_PASSIVE; // fill in my IP for me

	if ((status = getaddrinfo(addr, HCS_TCP_STATIC_PORT, &hints, &res)) != 0) {
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
	printf("\nPhase 1: The Health Center Server has port number %s and IP address %s.\n", HCS_TCP_STATIC_PORT, s);

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
		break; 		/*if we get here, we must have connected successfully*/
	}
	if (p == NULL) {
		/*looped off the end of the list with no successful bind*/
		fprintf(stderr, "failed to bind socket\n");
		exit(2);
	}

	freeaddrinfo(res); 		/*free the linked-list*/

	/*load user.txt file*/
	if((retVal = create_users()) < 0)
		return retVal;

	/*load availabilities.txt file*/
	if((retVal = create_availabilities()) < 0)
		return retVal;

	if(listen(sockfd, BACKLOG) == -1){
		printf("Failed to listen\n");
		return -1;
	}

#ifdef ENABLE_SIGCHLD
	/*code extracted from beej guide*/
	sa.sa_handler = sigchld_handler; // reap all dead processes
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}
#endif
	/*code extracted from beej guide*/
	while(1)
	{
		sin_size = sizeof their_addr;
		new_fd = 0;
		new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
		if (new_fd == -1)
		{
			/*perror("Healthcenterserver Error: accept");*/
			continue;
		}

		inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), s, sizeof s);
		int port = ntohs(((struct sockaddr_in *)&their_addr)->sin_port);
		if (!fork()) // this is the child process
		{
			close(sockfd); // child doesn't need the listener

			int number_of_bytes;
			memset(buf, '0' ,sizeof(buf));
			if ((number_of_bytes = recv(new_fd, buf, MAXBUFLEN-1, 0)) == -1)
			{
				perror("Healthcenterserver Error: when receiving bytes\n");
				exit(1);
			}

			buf[number_of_bytes] = '\0';

			struct users temp_patient;
			retVal = check_authentication((char *)buf, &temp_patient);

			printf("\nPhase 1: The Health Center Server has received request from a patient with username %s and password %s.\n", temp_patient.username, temp_patient.password);

			if(retVal == 1){
				if (send(new_fd, "success", 7, 0) == -1)
				{
					perror("Healthcenterserver Error: while sending\n");
					exit(1);
				}
				printf("\nPhase 1: The Health Center Server sends the response success to patient with username %s.\n", temp_patient.username);

				/*start of phase2 stage1*/
				retVal = phase2(&new_fd, &port, s);

				printf("\nPhase 2: The Health Center Server sends available time slots to patient with username %s.\n", temp_patient.username);

				memset(buf, '\0' ,sizeof(buf));
				if ((number_of_bytes = recv(new_fd, buf, MAXBUFLEN-1, 0)) == -1)
				{
					perror("Healthcenterserver Error: when receiving bytes\n");
					exit(1);
				}

				buf[number_of_bytes] = '\0';

				printf("\nPhase 2: The Health Center Server receives a request for appointment %c from patient with port number %d and username %s.\n", buf[10], port, temp_patient.username);
				/*end of phase2 stage1*/

				/*start of phase2 stage2*/
				char sendBuf[256];
				memset(sendBuf, '\0' ,sizeof(sendBuf));
				retVal = check_availability(buf, sendBuf);

				if(retVal == 1){
					printf("\nPhase 2: The Health Center Server confirms the following appointment %c to patient with username %s.\n", buf[10], temp_patient.username);
					if (send(new_fd, sendBuf, sizeof(sendBuf), 0) == -1)
					{
						perror("Healthcenterserver Error: while sending\n");
						exit(1);
					}
				}
				else{
					printf("\nPhase 2: The Health Center Server rejects the following appointment %c to patient with username %s.\n", buf[10], temp_patient.username);
					if (send(new_fd, "notavailable", 12, 0) == -1)
					{
						perror("Healthcenterserver Error: while sending\n");
						exit(1);
					}
				}
				memset(sendBuf, '\0' ,sizeof(sendBuf));
				/*end of phase2 stage2*/
			}
			else{
				if (send(new_fd, "failure", 7, 0) == -1)
				{
					perror("Healthcenterserver Error: while sending\n");
					exit(1);
				}
				printf("\nPhase 1: The Health Center Server sends the response failure to patient with username %s.\n", temp_patient.username);
			}
			close(new_fd);
			exit(0);
		}
		else
			close(new_fd);  /*parent doesn't need this*/
		/*while(wait(NULL) > 0);*/
	}
	while(wait(NULL) > 0);
	close(sockfd);
	return 0;
}

int main(void)
{
	/*using shared mapping*/
	av =  (AVAILABILITIES *)mmap(NULL, sizeof *av, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	/*using shared mapping*/
	m = (pthread_mutex_t *)mmap(NULL, sizeof *m, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	pthread_mutex_t m1 = PTHREAD_MUTEX_INITIALIZER;
	m = &m1;

	int retVal = 0;
	if(( retVal = phase1()) <= 0)
		return retVal;

	/*while(waitpid(-1, NULL, WNOHANG) > 0);*/

	munmap((void *)av, sizeof(*av));
	munmap((void *)m, sizeof(*m));

	return 0;
}
