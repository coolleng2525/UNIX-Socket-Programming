
#ifndef __PUBLICS_H__
#define __PUBLICS_H__
// #define US_SERVER_HOST "nunki.usc.edu"
#define US_SERVER_HOST "localhost"
#define DEBUG_AT() printf("At %s:%d\n", __FILE__, __LINE__)
#define DEBUG_PRINT(fmt, args... ) printf("At %s:%d " fmt "\n", __FILE__, __LINE__, ##args)

#define USER_FILE "users.txt"
#ifdef perror
#undef perror
#endif
#define perror(x) printf("AT %s:%d %s: %s\n", __FILE__, __LINE__ , x, strerror(errno))

#endif