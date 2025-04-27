//message.h

#ifndef MESSAGE_H
#define MESSAGE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>  // pour size_t

#include <sodium.h>

// Structures de messages

typedef struct {
    uint8_t CODE;
    uint16_t ID;
} QuitMessage;

typedef struct {
    uint8_t CODE;
    uint16_t ID;
    uint32_t NUMV;
    uint32_t PRIX;
} RejetMessage;

typedef struct {
    uint8_t CODE;
    uint16_t ID;
    uint32_t NUMV;
} DisparitionSuperviseurMessage;

typedef struct {
    uint8_t CODE;
    uint16_t ID;
    uint16_t NB;
    uint16_t ids[];
} DisparitionPairsMessage;

typedef struct {
    uint8_t CODE;
    uint16_t ID;
    uint32_t NUMV;
    uint32_t PRIX;
} FinalisationVenteMessage;

typedef struct {
    uint8_t CODE;
    uint16_t ID;
    uint32_t NUMV;
    uint32_t PRIX;
} VenteMessage;

typedef struct {
    uint8_t code;     // = 1
    uint16_t id;      // ID du pair
    uint8_t lmess;    // longueur du message signé
    uint8_t message[256];   // message signé
    uint8_t lsig;     // longueur de la signature (toujours 64 avec Ed25519)
    unsigned char signature[crypto_sign_BYTES]; // Signature Ed25519 (64 octets)
} ValidationMessageComplet;

typedef struct {
    uint8_t code;                      // 2
    uint16_t superviseur_id;           // ID du superviseur
    uint8_t lmess;                     // longueur du message signé
    unsigned char message[256];        // message signé
    uint8_t lsig;                      // longueur de la signature (toujours 64)
    unsigned char signature[crypto_sign_BYTES];  // signature Ed25519 (64 octets)
    uint16_t nb_validations;           // nombre de validations reçues
} FinalMessage;

typedef struct {
    int id;
    unsigned char message[256];
    unsigned char signature[crypto_sign_BYTES];
} SignedMessage;

#define PUBLIC_KEY_MSG_CODE 20
typedef struct {
    uint8_t code;                      // 20
    uint16_t id;                      // ID du pair
    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];  // 32 octets
} PublicKeyMessage;


// Déclaration des structures pour la récupération des champs
struct message {
    uint8_t code;
    uint16_t id;
    struct in6_addr ip;
    uint16_t port;
    char mess[256];  // Message optionnel
    char sig[256];   // Signature optionnelle
    uint32_t numv;   // Numéro de vente optionnel
    uint32_t prix;   // Prix optionnel
};

// Prototypes de fonctions
int msg_4 (uint8_t *msg, uint16_t id_peer, uint16_t port_tcp);
int parse_message(uint8_t *msg, size_t msg_len, struct message *msg_struct);

void envoyer_message(int socket, uint16_t id);
void envoyer_rejet(int socket, uint8_t code, uint16_t id, uint32_t numv, uint32_t prix);
void envoyer_vente(int socket, bool etape, uint16_t id, uint32_t numv, uint32_t prix);
void envoyer_finalisation_vente(int socket, bool etape, uint16_t id, uint32_t numv, uint32_t prix);
void envoyer_disparition(int socket, bool superviseur, uint16_t id, uint32_t numv, uint16_t *ids_disparus, uint16_t nb);
void envoyer_enchere(int socket, uint16_t id, uint32_t numv, uint32_t prix);
void envoyer_validation_complet(int socket, uint16_t id, const unsigned char *message, size_t message_len, const unsigned char *private_key);

#endif // MESSAGE_H
