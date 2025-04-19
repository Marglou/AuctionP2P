#ifndef PEER_H
#define PEER_H

#include <netinet/in.h>
#include <pthread.h>

#define PORT 12345
#define GROUP "ff15::abcd"
#define BUF_SIZE 1024

#define PORT_ENCHERE 12346
#define GROUP_ENCHERE "ff15::efgh"

#define MAX_ENCHERES 5

typedef struct {
    int sock;
    char group[INET6_ADDRSTRLEN];
    char id[64];
} EnchereSocket;


// Fonctions principales
void peer_start(const char *nom, const char *interface);
void creer_enchere();
void join_enchere(char *auction_id, char *auction_group);
void *auction_receiver(void *arg);
void *peer_receiver(void *arg);
void handle_sigint(int sig);

#endif // PEER_H
