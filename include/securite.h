// #ifndef SECURITE_H
// #define SECURITE_H

// #include <openssl/evp.h>

// void init_openssl();

// EVP_PKEY *load_private_key(const char *filename);
// EVP_PKEY *load_public_key(const char *filename);

// int generate_rsa_keys(const int bits, const char *pub_file, const char *priv_file);
// int generate_ed25519_keys(const char *pub_file, const char *priv_file);

// int sign_message(EVP_PKEY *privkey, unsigned char *msg, unsigned char **sig, size_t *siglen);
// int verify_signature(EVP_PKEY *pubkey, unsigned char *msg, unsigned char *sig, size_t siglen);

// int rsa_encrypt(EVP_PKEY *pubkey, unsigned char *msg, size_t msg_len, unsigned char **enc, size_t *enc_len);
// int rsa_decrypt(EVP_PKEY *privkey, unsigned char *enc, size_t enc_len, unsigned char **dec, size_t *dec_len);

// #endif
