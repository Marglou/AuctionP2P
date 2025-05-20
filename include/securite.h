#ifndef SECURITE_H
#define SECURITE_H

#include <openssl/evp.h>
#include <openssl/err.h>

#define MAX_PEERS 5

void init_superviseur();
void cleanup_superviseur();
int register_peer(const char *name, EVP_PKEY *pubkey);
EVP_PKEY* get_peer_pubkey(const char *name);

int verify_message(EVP_PKEY *pubkey, const unsigned char *msg, size_t msglen,
                   const unsigned char *sig, size_t siglen);

int generate_certificate_for_peer(const char *peer_name, char *cert_path, size_t cert_path_size, char *key_path, size_t key_path_size);
int get_public_key_size(const char *cert_path);
int generate_ed25519_keypair_and_extract_CLE(const char *key_path, unsigned char *CLE);


void init_openssl();

EVP_PKEY *convert_public_key_to_evp_pkey(char *pubkey);
EVP_PKEY *convert_private_key_to_evp_pkey(char *privkey);
int generate_ed25519_key(char* public_key_name, char* private_key_name);

int sign(EVP_PKEY *pkey, unsigned char *msg, unsigned char **sig, size_t *slen);
int verify(EVP_PKEY *pubkey, unsigned char *msg, unsigned char *sig, size_t slen);


#endif
