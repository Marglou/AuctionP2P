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

#ifndef ED25519_SIGNATURE_SIZE
#define ED25519_SIGNATURE_SIZE 64
#endif

// Structure for the peer list
typedef struct peer_list {
    uint16_t id;
    struct in6_addr ip;
    uint16_t port_tcp;
    unsigned char cle[113];
    struct peer_list *next;
} peer_list;


// Structure pour stocker les informations d'un pair
struct peer_info {
    uint16_t id;
    struct in6_addr ip;
    uint16_t port_tcp;
};


struct Multicast {
    int sock;                                // Socket UDP multicast
    struct sockaddr_in6 addr;                // Adresse multicast (pour sendto)
    struct ipv6_mreq mreq;                   // Pour abonnement (IPV6_JOIN_GROUP)
    uint16_t port;                                // Port du groupe
};

typedef struct {
    int sock;           // Socket de l'enchère
    // char group[INET6_ADDRSTRLEN];  // Groupe de l'enchère
    struct in6_addr group; // Adresse IPv6 du groupe d'enchère
    int id_enchere;     // ID de l'enchère
    int port_enchere; // Port de l'enchère
    int nb_pairs; // Nombre de pairs dans l'enchère
    int numv; // Numéro de la vente
    struct peer_list *liste_participants; // Liste des pairs de cette enchère
    int is_superviseur; // Indique si le pair est superviseur de l'enchère
} EnchereSocket;


struct tcp_listener_state {
    int socket_tcp;
    int socket_udp;
    volatile int response_received;
    time_t first_response_time;
};

typedef struct {
    int id_peer;
    char *pseudo;
    uint16_t port_perso;
    struct sockaddr_in6 adr_perso;
    EVP_PKEY *ed_privkey;
    EVP_PKEY *ed_pubkey;
    char *cert_path;

    SSL_CTX *ctx;

    int global_iface_index;
    int socket_tcp;
    int socket_udp;

    struct tcp_listener_state listener_tcp;
    struct peer_info discovered_peers[MAX_PEERS];
    size_t num_peers;

    EnchereSocket encheres[MAX_ENCHERES];
    int nb_encheres;
    int enchere_active;
    int cpt;
    struct Multicast adr_liaison;
    int join_en_cours; // Indique si le pair est en cours de jointure
} Peer;

typedef struct {
    char name[100];
    EVP_PKEY *pubkey;
} peer_key;

struct valid_peer {
    uint16_t id;
    uint8_t lsig;
    unsigned char sig[ED25519_SIGNATURE_SIZE];
    struct valid_peer *next;
};

extern int is_superviseur;
extern int enchere_supervise;
// extern struct Multicast adr_liaison; // Structure pour le multicast
extern Peer p;

// Fonctions principales
void peer_start(const char *nom);

void *auction_receiver(void *arg);
void handle_sigint(int sig);


// Peer management functions
// int find_peer_id(struct peer *p, uint16_t *id, bool find_free);
int add_peer(struct peer_list **head, uint16_t id, struct in6_addr ip, uint16_t port, unsigned char *cle);
void clean_peer();

void* listen_main_sockets(void* arg);
void *listen_tcp_thread(void *arg);

int connect_to_peers_and_send_info(peer_list *p, uint16_t new_peer_id, struct in6_addr new_peer_ip, 
                                  uint16_t new_peer_port, unsigned char *new_peer_cle);



#endif // PEER_H
 