// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <openssl/evp.h>
// #include <openssl/pem.h>
// #include <openssl/err.h>
// #include <openssl/rsa.h>
// #include <openssl/ssl.h>

// /* Initialisation OpenSSL */
// void init_openssl() {
//     SSL_load_error_strings();
//     OpenSSL_add_all_algorithms();
// }

// /* Convertit une clé privée PEM en EVP_PKEY */
// EVP_PKEY *load_private_key(const char *filename) {
//     EVP_PKEY *pkey = NULL;
//     FILE *fp = fopen(filename, "r");
//     if (!fp) { perror("fopen"); return NULL; }
//     PEM_read_PrivateKey(fp, &pkey, NULL, NULL);
//     fclose(fp);
//     return pkey;
// }

// /* Convertit une clé publique PEM en EVP_PKEY */
// EVP_PKEY *load_public_key(const char *filename) {
//     EVP_PKEY *pkey = NULL;
//     FILE *fp = fopen(filename, "r");
//     if (!fp) { perror("fopen"); return NULL; }
//     PEM_read_PUBKEY(fp, &pkey, NULL, NULL);
//     fclose(fp);
//     return pkey;
// }

// /* Génère une paire de clés RSA */
// int generate_rsa_keys(const int bits, const char *pub_file, const char *priv_file) {
//     EVP_PKEY *pkey = EVP_RSA_gen(bits);
//     if (!pkey) return 0;

//     FILE *pub = fopen(pub_file, "w+");
//     if (!pub) { perror("fopen"); return 0; }
//     if (!PEM_write_PUBKEY(pub, pkey)) return 0;
//     fclose(pub);

//     FILE *priv = fopen(priv_file, "w+");
//     if (!priv) { perror("fopen"); return 0; }
//     if (!PEM_write_PrivateKey(priv, pkey, NULL, NULL, 0, NULL, NULL)) return 0;
//     fclose(priv);

//     EVP_PKEY_free(pkey);
//     return 1;
// }

// /* Génère une paire de clés ED25519 */
// int generate_ed25519_keys(const char *pub_file, const char *priv_file) {
//     EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
//     EVP_PKEY *pkey = NULL;
//     if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_generate(ctx, &pkey) <= 0)
//         return 0;

//     FILE *pub = fopen(pub_file, "w+");
//     FILE *priv = fopen(priv_file, "w+");
//     if (!pub || !priv) return 0;

//     PEM_write_PUBKEY(pub, pkey);
//     PEM_write_PrivateKey(priv, pkey, NULL, NULL, 0, NULL, NULL);
//     fclose(pub); fclose(priv);

//     EVP_PKEY_free(pkey);
//     EVP_PKEY_CTX_free(ctx);
//     return 1;
// }

// /* Signature (RSA ou ED25519) */
// int sign_message(EVP_PKEY *privkey, unsigned char *msg, unsigned char **sig, size_t *siglen) {
//     EVP_MD_CTX *ctx = EVP_MD_CTX_new();
//     int ret = 0;
//     *sig = NULL;
//     if (!ctx) return 0;

//     if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, privkey) <= 0) goto end;

//     if (EVP_DigestSign(ctx, NULL, siglen, msg, strlen((char *)msg)) <= 0) goto end;

//     *sig = malloc(*siglen);
//     if (!*sig) goto end;

//     if (EVP_DigestSign(ctx, *sig, siglen, msg, strlen((char *)msg)) <= 0) goto end;

//     ret = 1;
// end:
//     if (!ret && *sig) { free(*sig); *sig = NULL; }
//     EVP_MD_CTX_free(ctx);
//     return ret;
// }

// /* Vérification de signature */
// int verify_signature(EVP_PKEY *pubkey, unsigned char *msg, unsigned char *sig, size_t siglen) {
//     EVP_MD_CTX *ctx = EVP_MD_CTX_new();
//     if (!ctx) return 0;

//     if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pubkey) <= 0) goto fail;
//     int result = EVP_DigestVerify(ctx, sig, siglen, msg, strlen((char *)msg));
//     EVP_MD_CTX_free(ctx);
//     return result == 1;

// fail:
//     EVP_MD_CTX_free(ctx);
//     return 0;
// }

// /* Chiffrement RSA (petit message) */
// int rsa_encrypt(EVP_PKEY *pubkey, unsigned char *msg, size_t msg_len, unsigned char **enc, size_t *enc_len) {
//     EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubkey, NULL);
//     if (!ctx) return 0;

//     if (EVP_PKEY_encrypt_init(ctx) <= 0) return 0;
//     if (EVP_PKEY_encrypt(ctx, NULL, enc_len, msg, msg_len) <= 0) return 0;

//     *enc = malloc(*enc_len);
//     if (!*enc) return 0;

//     int ret = EVP_PKEY_encrypt(ctx, *enc, enc_len, msg, msg_len);
//     EVP_PKEY_CTX_free(ctx);
//     return ret > 0;
// }

// /* Déchiffrement RSA */
// int rsa_decrypt(EVP_PKEY *privkey, unsigned char *enc, size_t enc_len, unsigned char **dec, size_t *dec_len) {
//     EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey, NULL);
//     if (!ctx) return 0;

//     if (EVP_PKEY_decrypt_init(ctx) <= 0) return 0;
//     if (EVP_PKEY_decrypt(ctx, NULL, dec_len, enc, enc_len) <= 0) return 0;

//     *dec = malloc(*dec_len);
//     if (!*dec) return 0;

//     int ret = EVP_PKEY_decrypt(ctx, *dec, dec_len, enc, enc_len);
//     EVP_PKEY_CTX_free(ctx);
//     return ret > 0;
// }
