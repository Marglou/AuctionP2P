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

extern EnchereSocket encheres[MAX_ENCHERES];
extern int nb_encheres;    // Nombre d'enchères rejointes
extern int enchere_active; // Index dans encheres[]
extern int cpt; // Compteur pour les enchères qu'il a initié
extern char id_peer[128]; // ID du pair
extern int global_sock; // Socket global
extern char nom[100]; // Nom du pair
extern int global_iface_index; // Index de l'interface réseau

extern int socket_tcp; // Socket TCP pour la connexion
extern int port_tcp; // Port TCP pour la connexion



// Fonctions principales
void peer_start(const char *nom, const char *interface);

void *auction_receiver(void *arg);
void *peer_receiver(void *arg);
void handle_sigint(int sig);

void generer_id_peer(const char *nom, char *ipv6_perso);


int create_tcp_socket_serveur();
int create_tcp_socket_client(const char *ip_dest, int port_dest);

#endif // PEER_H
