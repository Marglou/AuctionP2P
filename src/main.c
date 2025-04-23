//main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/peer.h"
#include "../include/superviseur.h"
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

EVP_PKEY *my_privkey = NULL;
EVP_PKEY *my_pubkey = NULL;

int main() {
    if (OPENSSL_init_crypto(0, NULL) == 0) {
        fprintf(stderr, "Failed to initialize OpenSSL\n");
        return 1;
    }

    char nom[100];
    printf("Nom du pair : ");
    fflush(stdout);
    fgets(nom, sizeof(nom), stdin);
    nom[strcspn(nom, "\n")] = '\0';

    init_superviseur();

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
