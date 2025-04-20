//superviseur.c
#include "../include_2/peer.h"
#include "../include_2/superviseur.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static Peer peers[MAX_PEERS];
static int peer_count = 0;

void init_superviseur() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    peer_count = 0;
}

void cleanup_superviseur() {
    for (int i = 0; i < peer_count; i++) {
        EVP_PKEY_free(peers[i].pubkey);
    }
    EVP_cleanup();
    ERR_free_strings();
}

int register_peer(const char *name, EVP_PKEY *pubkey) {
    if (peer_count >= MAX_PEERS) return -1;
    strncpy(peers[peer_count].name, name, sizeof(peers[peer_count].name));
    peers[peer_count].pubkey = pubkey;
    peer_count++;
    return 0;
}

EVP_PKEY* get_peer_pubkey(const char *name) {
    for (int i = 0; i < peer_count; i++) {
        if (strcmp(peers[i].name, name) == 0) {
            return peers[i].pubkey;
        }
    }
    return NULL;
}

EVP_PKEY* generate_ed25519_key() {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!pctx) return NULL;

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

int sign_message(EVP_PKEY *privkey, const unsigned char *msg, size_t msglen,
                 unsigned char *sig, size_t *siglen) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return 0;

    int result = 0;
    if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, privkey) == 1 &&
        EVP_DigestSign(mdctx, sig, siglen, msg, msglen) == 1) {
        result = 1;
    }

    EVP_MD_CTX_free(mdctx);
    return result;
}

int verify_message(EVP_PKEY *pubkey, const unsigned char *msg, size_t msglen,
                   const unsigned char *sig, size_t siglen) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return 0;

    int result = 0;
    if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pubkey) == 1 &&
        EVP_DigestVerify(mdctx, sig, siglen, msg, msglen) == 1) {
        result = 1;
    }

    EVP_MD_CTX_free(mdctx);
    return result;
}
