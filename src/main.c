//main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/peer.h"
#include "../include/superviseur.h"
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

EVP_PKEY *my_privkey = NULL;
EVP_PKEY *my_pubkey = NULL;


#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>


int main() {

    char nom[100];  // Déclaration du tableau pour le nom du pair

    // Demander le nom de l'utilisateur
    printf("Nom du pair : ");
    fflush(stdout);  // Assurer que le message est bien affiché avant la lecture de l'entrée

    // Lire l'entrée de l'utilisateur
    fgets(nom, sizeof(nom), stdin); 

    // Enlever le caractère de nouvelle ligne '\n' si présent
    nom[strcspn(nom, "\n")] = '\0';

    peer_start(nom);

    return 0;
}
