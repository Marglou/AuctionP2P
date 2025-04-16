//superviseur.h

#ifndef SUPERVISEUR_H
#define SUPERVISEUR_H

#include <netinet/in.h>
#include <sodium.h>

#define SUPERVISEUR_PORT 12346

typedef struct {
    uint16_t id;
    unsigned char private_key[crypto_sign_SECRETKEYBYTES];
    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
    struct sockaddr_in6 addr;
} Superviseur;

void init_superviseur(Superviseur *s, uint16_t id, uint16_t port);
void* handler_superviseur(void* arg);

#endif
