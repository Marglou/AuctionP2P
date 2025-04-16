//peer.h

#ifndef PEER_H
#define PEER_H

#include <netinet/in.h>  // pour struct sockaddr_in6
#include <sodium.h>     

#define MULTICAST_GROUP "ff02::1"
#define PEER_PORT 12345
#define BUFFER_SIZE 1024
#define MAX_PEERS 4

// Variables globales (déclarées dans main.c)
extern int active_peers;
extern pthread_mutex_t peer_count_mutex;

// Déclaration des clés publiques de tous les pairs
extern unsigned char public_keys[MAX_PEERS][crypto_sign_PUBLICKEYBYTES];
extern unsigned char private_keys[MAX_PEERS][crypto_sign_SECRETKEYBYTES];


// Définition de la structure pour un pair
typedef struct {
    int id;
    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
    unsigned char private_key[crypto_sign_SECRETKEYBYTES];
} Peer;


// Fonctions du peer
void *start_listener(void *arg);
void send_multicast_message(int sock, struct sockaddr_in6 *multicast_addr, const char *message);
void *peer_handler(void *arg);


// Génération des clés (privée et publique)
void generate_keys_for_peer(Peer *peer);

// Fonction de signature
int sign_message(const unsigned char *message, size_t message_len, unsigned char *signed_message, unsigned char *private_key);

// Fonction de vérification de la signature
int verify_signature(const unsigned char *message, size_t message_len, const unsigned char *signature, const unsigned char *public_key);

// Fonction d'envoi de la clé publique
void envoyer_cle_publique(int sock, uint16_t id, unsigned char *public_key, struct sockaddr_in6 *superviseur_addr);


#endif 
