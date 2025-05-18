//peer.h
#ifndef PEER_H
#define PEER_H

#include <netinet/in.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <stdbool.h>

#define PORT 12365
#define GROUP "ff12::abcd"
#define BUF_SIZE 1024

#define MAX_ENCHERES 5
#define MAX_PEERS 5

typedef struct {
    int sock;           // Socket de l'enchère
    // char group[INET6_ADDRSTRLEN];  // Groupe de l'enchère
    struct in6_addr group; // Adresse IPv6 du groupe d'enchère
    int id_enchere;     // ID de l'enchère
    int port_enchere; // Port de l'enchère
    int nb_pairs; // Nombre de pairs dans l'enchère
    struct peer *liste_participants; // Liste des pairs de cette enchère
} EnchereSocket;

// Structure for the peer list
typedef struct peer {
    uint16_t id;
    struct in6_addr ip;
    uint16_t port_tcp;
    unsigned char cle[113];
    struct peer *next;
}peer;

typedef struct {
    char name[100];
    EVP_PKEY *pubkey;
} Peer;



// Structure pour stocker les informations d'un pair
struct peer_info {
    uint16_t id;
    struct in6_addr ip;
    uint16_t port_tcp;
};

struct udp_thread_args {
    int sock;
};

struct Multicast {
    int sock;                                // Socket UDP multicast
    struct sockaddr_in6 addr;                // Adresse multicast (pour sendto)
    struct ipv6_mreq mreq;                   // Pour abonnement (IPV6_JOIN_GROUP)
    uint16_t port;                                // Port du groupe
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
extern int global_iface_index; // Index de l'interface réseau

extern int socket_tcp, socket_udp; // Socket TCP pour la connexion
extern uint16_t port_perso; // Ports TCP et UDP
extern struct tcp_listener_state listener_tcp; // État du listener TCP
extern struct sockaddr_in6 adr_perso; // Adresse IPv6 personnelle

extern struct peer_info discovered_peers[MAX_PEERS]; // Liste des pairs découverts
extern size_t num_peers; // Nombre de pairs découverts

extern char* pseudo;

extern int is_superviseur;
extern int enchere_supervise;
extern struct Multicast adr_liaison; // Structure pour le multicast


// Fonctions principales
void peer_start(const char *nom);

void *auction_receiver(void *arg);
void handle_sigint(int sig);


// Peer management functions
// int find_peer_id(struct peer *p, uint16_t *id, bool find_free);
int add_peer(struct peer **head, uint16_t id, struct in6_addr ip, uint16_t port, unsigned char *cle);
void clean_peer();

void* listen_main_sockets(void* arg);
void *listen_tcp_thread(void *arg);



#endif // PEER_H
 