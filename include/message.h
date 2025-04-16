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

// Prototypes de fonctions

void envoyer_message(int socket, uint16_t id);
void envoyer_rejet(int socket, uint8_t code, uint16_t id, uint32_t numv, uint32_t prix);
void envoyer_vente(int socket, bool etape, uint16_t id, uint32_t numv, uint32_t prix);
void envoyer_finalisation_vente(int socket, bool etape, uint16_t id, uint32_t numv, uint32_t prix);
void envoyer_disparition(int socket, bool superviseur, uint16_t id, uint32_t numv, uint16_t *ids_disparus, uint16_t nb);
void envoyer_enchere(int socket, uint16_t id, uint32_t numv, uint32_t prix);
void envoyer_validation_complet(int socket, uint16_t id, const unsigned char *message, size_t message_len, const unsigned char *private_key);

#endif // MESSAGE_H
