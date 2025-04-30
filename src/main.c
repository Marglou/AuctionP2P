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

void init_openssl()
{
    SSL_library_init();           // Ancienne API, toujours utile pour compatibilité
    SSL_load_error_strings();    // Messages d’erreur
    OpenSSL_add_all_algorithms(); // Initialiser les algorithmes
    OPENSSL_init_ssl(0, NULL);    // Nouvelle API (facultative mais plus propre)
}


int main() {

    char nom[100];
    printf("Nom du pair : ");
    fflush(stdout);
    fgets(nom, sizeof(nom), stdin);
    nom[strcspn(nom, "\n")] = '\0';

    init_superviseur();
    init_openssl();

    my_privkey = generate_ed25519_key();
    if (!my_privkey) {
        fprintf(stderr, "Error generating private key.\n");
        cleanup_superviseur();
        CRYPTO_cleanup_all_ex_data();
        ERR_free_strings();
        return 1;
    }

    my_pubkey = EVP_PKEY_dup(my_privkey);
    if (!my_pubkey) {
        fprintf(stderr, "Error duplicating public key.\n");
        // Handle error appropriately
        EVP_PKEY_free(my_privkey);
        cleanup_superviseur();
        return 1;
    }

    register_peer(nom, my_pubkey);

    // peer_start(nom, "en0");  // Pour MAC
    // peer_start(nom, "eth0");  
    peer_start(nom, "enp0s3");

    cleanup_superviseur();
    EVP_PKEY_free(my_privkey);
    EVP_PKEY_free(my_pubkey);
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}
