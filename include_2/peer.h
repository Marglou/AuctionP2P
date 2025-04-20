//peer.h
#ifndef PEER_H
#define PEER_H

#include <netinet/in.h>
#include <pthread.h>
#include <openssl/evp.h>

#define PORT 12365
#define GROUP "ff15::abcd"
#define BUF_SIZE 1024

#define PORT_ENCHERE 12366
#define GROUP_ENCHERE "ff15::efgh"

#define MAX_ENCHERES 5

typedef struct {
    int sock;
    char group[INET6_ADDRSTRLEN];
    char id[64];
} EnchereSocket;

typedef struct {
    char name[100];
    EVP_PKEY *pubkey;
} Peer;

// Global variables for private and public keys
extern EVP_PKEY *my_privkey;
extern EVP_PKEY *my_pubkey;

// Fonctions principales
void peer_start(const char *nom, const char *interface);
void creer_enchere();
void join_enchere(const char *id, const char *group);
void *auction_receiver(void *arg);
void *peer_receiver(void *arg);
void handle_sigint(int sig);
void generer_id_peer(const char *nom, char *ipv6_perso);

#endif // PEER_H
