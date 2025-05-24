//message.h

#ifndef MESSAGE_H
#define MESSAGE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>  
#include <openssl/evp.h>
#include "../include/peer.h"

// Constants for key sizes
#define ED25519_PUBLIC_KEY_SIZE 60
#define ED25519_SIGNATURE_SIZE 64
#define ED25519_KEY_WITH_HEADER_SIZE 113
#define PUBLIC_KEY_MSG_CODE 20

typedef struct {
    uint8_t code;     // = 11
    uint16_t id;      // ID du superviseur
    uint32_t numv;    // Numéro de vente
    uint32_t prix;    // Prix de la dernière enchère validée ou prix initial
} FinalizationWarningMessage;

typedef struct {
    uint8_t code;     // = 12
    uint16_t id;      // ID du gagnant ou du superviseur
    uint32_t numv;    // Numéro de vente
    uint32_t prix;    // Prix final de l'enchère
} FinalizationMessage;

// Déclaration des structures pour la récupération des champs
// Structure unique pour tous les messages
struct message_4 {
    uint8_t code;
    uint16_t id;
    struct in6_addr ip;
    uint16_t port;
};

struct message_5 {
    uint8_t code;     // = 5
    uint16_t id;      // ID du pair
    struct in6_addr ip;  // Adresse IP (16 octets)
    uint16_t port;    // Port TCP
    unsigned char cle[113];  // Clé publique ED25519 (113 octets)
};

struct message_50 {
    uint8_t code;     // = 50
};

struct message_51 {
    uint8_t code;     // = 51
    uint16_t id;      // ID accepté
};

struct message_13 {
    uint8_t code;     // = 51
    uint16_t id;      // ID accepté
};

struct message_6 {
    uint8_t code;     // = 6
    uint16_t id;      // ID du pair P
    struct in6_addr ip;  // Adresse IP de P (16 octets)
    uint16_t port;    // Port TCP de P
    unsigned char cle[113];  // Clé publique ED25519 de P (113 octets)
};

typedef struct msg7_peer {
    uint16_t id;
    struct in6_addr ip;
    uint16_t port;
    unsigned char cle[113];
    struct msg7_peer *next;
} msg7_peer;

typedef struct message_7 {
    uint16_t id_q;
    struct in6_addr ip_enchere;
    uint16_t port_enchere;
    uint16_t nb;
    msg7_peer *liste_peers;
} message_7;

struct message_8 {
    uint8_t code;     
    uint16_t id;      // ID du pair P
    uint32_t numv; 
    uint32_t prix;    // Port TCP de P
};

// PARTIE CONSENSUS 
struct message_1 {
    uint8_t code;       // CODE, ici = 1
    uint16_t id;        // ID du pair 
    uint8_t lmess;      // longueur du message MESS
    char mess[256];         // pointeur vers message 
    uint8_t lsig;       // longueur de la signature
    unsigned char sig[ED25519_SIGNATURE_SIZE]; // pointeur vers signature binaire
};

struct message_2 {
    uint8_t code;       // CODE, ici = 2
    uint16_t id;        // ID du superviseur 
    uint8_t lmess;      // longueur du message MESS
    char mess[256];     // message 
    uint8_t lsig;       // longueur de la signature du superviseur
    unsigned char sig[ED25519_SIGNATURE_SIZE]; // signature du superviseur
    uint16_t nb_validations; // nombre de validations reçues 

    // Pour stocker jusqu'à 3 signatures de pairs (cas NB <= 3)
    uint16_t ids[3];
    uint8_t siglens[3];
    unsigned char sigs[3][ED25519_SIGNATURE_SIZE];
};

// Message code 18 - Remove absent peers
struct message_18 {
    uint8_t code;     // = 18
    uint16_t id;      // ID of peer P (supervisor)
    uint16_t nb;      // Number of absent peers
    uint16_t ids[];   // Array of absent peer IDs
};

struct message_16_17 {
    uint8_t code;     
    uint16_t id;      
    uint32_t numv;    
};

struct message_30 {
    uint8_t code;     
    uint32_t numv;    
    uint8_t lmess;      
    char mess[256];      
};

//--------------------------------------------------------------------------------------------------
int msg_4 (uint8_t *msg, uint16_t id_peer, uint16_t port_tcp);
int parse_msg_4 (uint8_t *msg, size_t msg_len, struct message_4 *msg_struct);

int msg_5 (uint8_t *msg, uint16_t id_peer, uint16_t port_tcp, struct in6_addr ip, unsigned char *public_key);
int parse_msg_5 (uint8_t *msg, size_t msg_len, struct message_5 *msg_struct);

int msg_50(uint8_t *msg);
int parse_msg_50(uint8_t *msg, size_t msg_len, struct message_50 *msg_struct);

int msg_51(uint8_t *msg, uint16_t id);
int parse_msg_51(uint8_t *msg, size_t msg_len, struct message_51 *msg_struct);

int msg_6(uint8_t *msg, uint16_t id_peer, struct in6_addr ip, uint16_t port_tcp, unsigned char *cle);
int parse_msg_6(uint8_t *msg, size_t msg_len, struct message_6 *msg_struct);

int message_7_header(uint8_t *buffer, size_t buffer_size, EnchereSocket q);
void envoyer_infos_peers(int socket, EnchereSocket *enchere);
int recevoir_message_7_header(int socket, EnchereSocket *enchere);
int recevoir_infos_peer(int socket, EnchereSocket *enchere);

int msg_8_9_10(uint8_t *msg, uint8_t code, uint16_t id, uint32_t numv, uint32_t prix);
int msg_14_15(uint8_t *msg, uint8_t code, uint16_t id, uint32_t numv, uint32_t prix);
int msg_11(uint8_t *msg, uint16_t id, uint32_t numv, uint32_t prix);
int msg_12(uint8_t *msg, uint16_t id, uint32_t numv, uint32_t prix);
int msg_13(uint8_t *msg, uint16_t id);
int parse_msg_8_9_10(uint8_t *msg, size_t msg_len, struct message_8 *msg_struct);
int parse_msg_11(uint8_t *msg, size_t msg_len, FinalizationWarningMessage *msg_struct);
int parse_msg_12(uint8_t *msg, size_t msg_len, FinalizationMessage *msg_struct);
int parse_msg_13(uint8_t *msg, size_t msg_len, struct message_13 *msg_struct);

int msg_1(uint8_t *msg, uint16_t id, char *mess, uint8_t *sig, uint8_t siglen);
int parse_msg_1(const unsigned char *buf, size_t buflen, struct message_1 *msg_out);
int parse_msg_1(const uint8_t *buf, size_t len, struct message_1 *msg);

int msg_2(uint8_t *msg, uint16_t id, char *mess, uint8_t *sig, uint8_t siglen, uint16_t nb_validations,
          uint16_t *ids, uint8_t *siglens, unsigned char **sigs);
int parse_msg_2(const uint8_t *buf, size_t len, struct message_2 *msg);

int msg_20(uint8_t *msg, uint16_t id, uint16_t nb, uint16_t *peer_ids, uint8_t *sig_lengths, uint8_t **signatures);

int get_adresse_perso_from_socket(int sock, struct in6_addr *addr);

int msg_18(uint8_t *msg, uint16_t id, uint16_t nb, uint16_t *ids);
int parse_msg_18(uint8_t *msg, size_t msg_len, struct message_18 *msg_struct);

int msg_16_17(uint8_t *msg, uint8_t code, uint16_t id, uint32_t numv);
int parse_msg_16_17(uint8_t *msg, size_t msg_len, struct message_16_17 *msg_struct);
int msg_30(uint8_t *buf, uint32_t numv, char *mess);
int parse_msg_30 (uint8_t *msg, size_t len, struct message_30 *out);

#endif 
