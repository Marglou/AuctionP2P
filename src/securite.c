#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>  // pour mkdir
#include <sys/types.h> // optionnel, mais recommandé avec mkdir
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "../include/peer.h"

static peer_key peers[MAX_PEERS];
static int peer_count = 0;


/* Initialisation OpenSSL */
void init_openssl() {
    OpenSSL_add_all_algorithms();
}

/* Convertit une clé privée PEM en EVP_PKEY */
EVP_PKEY *load_private_key(const char *filename) {
    EVP_PKEY *pkey = NULL;
    FILE *fp = fopen(filename, "r");
    if (!fp) { perror("fopen"); return NULL; }
    PEM_read_PrivateKey(fp, &pkey, NULL, NULL);
    fclose(fp);
    return pkey;
}

/* Convertit une clé publique PEM en EVP_PKEY */
EVP_PKEY *load_public_key(const char *filename) {
    EVP_PKEY *pkey = NULL;
    FILE *fp = fopen(filename, "r");
    if (!fp) { perror("fopen"); return NULL; }
    PEM_read_PUBKEY(fp, &pkey, NULL, NULL);
    fclose(fp);
    return pkey;
}

/* Génère une paire de clés RSA */
int generate_rsa_keys(const int bits, const char *pub_file, const char *priv_file) {
    EVP_PKEY *pkey = EVP_RSA_gen(bits);
    if (!pkey) return 0;

    FILE *pub = fopen(pub_file, "w+");
    if (!pub) { perror("fopen"); return 0; }
    if (!PEM_write_PUBKEY(pub, pkey)) return 0;
    fclose(pub);

    FILE *priv = fopen(priv_file, "w+");
    if (!priv) { perror("fopen"); return 0; }
    if (!PEM_write_PrivateKey(priv, pkey, NULL, NULL, 0, NULL, NULL)) return 0;
    fclose(priv);

    EVP_PKEY_free(pkey);
    return 1;
}

/* Génère une paire de clés ED25519 */
int generate_ed25519_keys(const char *pub_file, const char *priv_file) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY *pkey = NULL;
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_generate(ctx, &pkey) <= 0)
        return 0;

    FILE *pub = fopen(pub_file, "w+");
    FILE *priv = fopen(priv_file, "w+");
    if (!pub || !priv) return 0;

    PEM_write_PUBKEY(pub, pkey);
    PEM_write_PrivateKey(priv, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(pub); fclose(priv);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return 1;
}

/* Signature (RSA ou ED25519) */
int sign_message(EVP_PKEY *privkey, unsigned char *msg, unsigned char **sig, size_t *siglen) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ret = 0;
    *sig = NULL;
    if (!ctx) return 0;

    if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, privkey) <= 0) goto end;

    if (EVP_DigestSign(ctx, NULL, siglen, msg, strlen((char *)msg)) <= 0) goto end;

    *sig = malloc(*siglen);
    if (!*sig) goto end;

    if (EVP_DigestSign(ctx, *sig, siglen, msg, strlen((char *)msg)) <= 0) goto end;

    ret = 1;
end:
    if (!ret && *sig) { free(*sig); *sig = NULL; }
    EVP_MD_CTX_free(ctx);
    return ret;
}

/* Vérification de signature */
int verify_signature(EVP_PKEY *pubkey, unsigned char *msg, unsigned char *sig, size_t siglen) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;

    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pubkey) <= 0) goto fail;
    int result = EVP_DigestVerify(ctx, sig, siglen, msg, strlen((char *)msg));
    EVP_MD_CTX_free(ctx);
    return result == 1;

fail:
    EVP_MD_CTX_free(ctx);
    return 0;
}



void init_superviseur()
{
    OpenSSL_add_all_algorithms();
    peer_count = 0;
}

void cleanup_superviseur()
{
    for (int i = 0; i < peer_count; i++)
    {
        EVP_PKEY_free(peers[i].pubkey);
    }
    EVP_cleanup();
}

int register_peer(const char *name, EVP_PKEY *pubkey)
{
    if (peer_count >= MAX_PEERS)
        return -1;
    strncpy(peers[peer_count].name, name, sizeof(peers[peer_count].name));
    peers[peer_count].pubkey = pubkey;
    peer_count++;
    return 0;
}

EVP_PKEY *get_peer_pubkey(const char *name)
{
    for (int i = 0; i < peer_count; i++)
    {
        if (strcmp(peers[i].name, name) == 0)
        {
            return peers[i].pubkey;
        }
    }
    return NULL;
}

EVP_PKEY *generate_ed25519_key()
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!pctx)
        return NULL;

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_keygen(pctx, &pkey) <= 0)
    {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(pctx);
    return pkey;
}


int verify_message(EVP_PKEY *pubkey, const unsigned char *msg, size_t msglen,
                   const unsigned char *sig, size_t siglen)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        return 0;

    int result = 0;
    if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pubkey) == 1 &&
        EVP_DigestVerify(mdctx, sig, siglen, msg, msglen) == 1)
    {
        result = 1;
    }

    EVP_MD_CTX_free(mdctx);
    return result;
}


int generate_certificate_for_peer(const char *peer_name, char *cert_path, size_t cert_path_size,
                                          char *key_path, size_t key_path_size)
{
    char dir_path[256];

    // Crée les dossiers certs/ et certs/<peer_name>
    snprintf(dir_path, sizeof(dir_path), "certs/%s", peer_name);
    mkdir("certs", 0755);
    mkdir(dir_path, 0755);

    // Définir chemins des fichiers .pem
    snprintf(key_path, key_path_size, "%s/key.pem", dir_path);
    snprintf(cert_path, cert_path_size, "%s/cert.pem", dir_path);

    // Générer la clé privée ed25519
    char genkey_cmd[512];
    snprintf(genkey_cmd, sizeof(genkey_cmd),
             "openssl genpkey -algorithm ed25519 -out %s >/dev/null 2>&1", key_path);

    if (system(genkey_cmd) != 0)
    {
        fprintf(stderr, "Erreur génération clé ed25519\n");
        return -1;
    }

    // Générer un certificat auto-signé à partir de la clé
    char req_cmd[1024];
    snprintf(req_cmd, sizeof(req_cmd),
             "openssl req -new -x509 -key %s -out %s -days 365 -subj \"/CN=%s\" >/dev/null 2>&1",
             key_path, cert_path, peer_name);

    if (system(req_cmd) != 0)
    {
        fprintf(stderr, "Erreur génération certificat ed25519\n");
        return -1;
    }

    return 0;
}

int get_public_key_size(const char *cert_path) {
    FILE *fp = fopen(cert_path, "r");
    if (!fp) {
        perror("fopen");
        return -1;
    }

    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!cert) {
        fprintf(stderr, "Erreur lecture certificat\n");
        return -1;
    }

    EVP_PKEY *pubkey = X509_get_pubkey(cert);
    X509_free(cert);
    if (!pubkey) {
        fprintf(stderr, "Erreur extraction clé publique\n");
        return -1;
    }

    int size_bytes = EVP_PKEY_get_size(pubkey);  // Pour Ed25519 : 32
    EVP_PKEY_free(pubkey);

    return size_bytes;
}





// Génère paire ED25519 et extrait la clé publique au format PEM (CLE de 113 octets)
int generate_ed25519_keypair_and_extract_CLE(const char *key_path, unsigned char *CLE) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "Erreur génération de la clé ED25519\n");
        return -1;
    }

    // Sauvegarde de la clé privée
    FILE *f = fopen(key_path, "w");
    if (!f || PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        fprintf(stderr, "Erreur écriture clé privée\n");
        return -1;
    }
    fclose(f);

    // Conversion de la clé publique en PEM dans une buffer mémoire
    BIO *mem = BIO_new(BIO_s_mem());
    if (!mem || PEM_write_bio_PUBKEY(mem, pkey) != 1) {
        fprintf(stderr, "Erreur écriture clé publique en mémoire\n");
        return -1;
    }

    // Lire le contenu PEM (devrait faire 113 octets)
    int len = BIO_read(mem, CLE, 113);
    CLE[len] = '\0';
    BIO_free(mem);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    if (len != 113) {
        fprintf(stderr, "Clé publique ED25519 invalide (taille %d au lieu de 113)\n", len);
        return -1;
    }

    return 0;
}
