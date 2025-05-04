//peer.h
#ifndef PEER_H
#define PEER_H

#include <netinet/in.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <stdbool.h>

#define PORT 12365
#define GROUP "ff15::abcd"
#define BUF_SIZE 1024

#define PORT_ENCHERE 12366
#define GROUP_ENCHERE "ff15::efgh"

#define MAX_ENCHERES 5
#define MAX_PEERS 5


// typedef struct {
//     int sock;
//     char group[INET6_ADDRSTRLEN];
//     int id_enchere;
// } EnchereSocket;

typedef struct {
    int sock;
    char group[INET6_ADDRSTRLEN];
    int id_enchere;

    struct peer *liste_participants; // Liste des pairs de cette enchère
} EnchereSocket;


typedef struct {
    char name[100];
    EVP_PKEY *pubkey;
} Peer;

// Structure for the peer list
struct peer {
    uint16_t id;
    struct in6_addr ip;
    uint16_t port_tcp;
    unsigned char cle[113];
    struct peer *next;
};

// Structure pour stocker les informations d'un pair
struct peer_info {
    uint16_t id;
    struct in6_addr ip;
    uint16_t port_tcp;
};


// Global variables for private and public keys
extern EVP_PKEY *my_privkey;
extern EVP_PKEY *my_pubkey;

extern EnchereSocket encheres[MAX_ENCHERES];
extern int nb_encheres;    // Nombre d'enchères rejointes
extern int enchere_active; // Index dans encheres[]
extern int cpt; // Compteur pour les enchères qu'il a initié
extern int id_peer; 
extern int global_sock; // Socket global
extern char nom[100]; // Nom du pair
extern int global_iface_index; // Index de l'interface réseau

extern int socket_tcp; // Socket TCP pour la connexion
extern int port_tcp; // Port TCP pour la connexion
extern struct tcp_listener_state listener_tcp; // État du listener TCP

extern struct peer_info discovered_peers[MAX_PEERS]; // Liste des pairs découverts
extern size_t num_peers; // Nombre de pairs découverts

extern char* pseudo;

extern int is_superviseur;
extern int enchere_supervise;


// Fonctions principales
void peer_start(const char *nom, const char *interface);

void *auction_receiver(void *arg);
void *peer_receiver(void *arg);
void handle_sigint(int sig);

int generer_id_peer();

int create_tcp_socket_serveur();
int create_tcp_socket_client(const char *ip_dest, int port_dest);
int get_adresse_perso_par_index(struct in6_addr *addr, unsigned int iface_index) ;

// Peer management functions
// int find_peer_id(struct peer *p, uint16_t *id, bool find_free);
// int add_peer(struct peer *p, uint16_t id, struct in6_addr ip, uint16_t port, unsigned char *cle);

#endif // PEER_H
