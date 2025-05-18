#ifndef SECURITE_H
#define SECURITE_H

#include <openssl/evp.h>
#include <openssl/err.h>

#define MAX_PEERS 5

void init_superviseur();
void cleanup_superviseur();
int register_peer(const char *name, EVP_PKEY *pubkey);
EVP_PKEY* get_peer_pubkey(const char *name);

EVP_PKEY* generate_ed25519_key();
int verify_message(EVP_PKEY *pubkey, const unsigned char *msg, size_t msglen,
                   const unsigned char *sig, size_t siglen);

int generate_certificate_for_peer(const char *peer_name, char *cert_path, size_t cert_path_size, char *key_path, size_t key_path_size);
int get_public_key_size(const char *cert_path);
int generate_ed25519_keypair_and_extract_CLE(const char *key_path, unsigned char *CLE);


void init_openssl();

EVP_PKEY *load_private_key(const char *filename);
EVP_PKEY *load_public_key(const char *filename);

int generate_rsa_keys(const int bits, const char *pub_file, const char *priv_file);
int generate_ed25519_keys(const char *pub_file, const char *priv_file);

int sign_message(EVP_PKEY *privkey, unsigned char *msg, unsigned char **sig, size_t *siglen);
int verify_signature(EVP_PKEY *pubkey, unsigned char *msg, unsigned char *sig, size_t siglen);



#endif
