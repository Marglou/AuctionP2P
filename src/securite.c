/*
 * Ce fichier contient des fonctions utilitaires pour la gestion des clés cryptographiques
 * et des opérations associées, utilisant la bibliothèque OpenSSL. 
 * 
 * Fonctionnalités principales :
 * 1. Gestion des clés ED25519 
 * 2. Signature et vérification 
 * 3. Gestion des certificats 
 * 4. Gestion des pairs ("peers") 
 * 5. Initialisation et nettoyage OpenSSL 
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>  
#include <sys/types.h> 
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include "../include/peer.h"

static peer_key peers[MAX_PEERS];
static int peer_count = 0;

void cleanup_ssl_connection(SSL *ssl) {
    if (ssl) {
        int sock = SSL_get_fd(ssl);
        SSL_shutdown(ssl);
        if (sock >= 0) close(sock);
        SSL_free(ssl);
    }
}

/* Initialisation OpenSSL */
void init_openssl() {
    OpenSSL_add_all_algorithms();
}

/* Convertit une clé privée PEM en EVP_PKEY */
EVP_PKEY *convert_public_key_to_evp_pkey(char *pubkey) {
	EVP_PKEY *pkey = NULL; 
	FILE *fp = fopen(pubkey, "r");
	if(fp == NULL){
		perror("fopen");
		return NULL;
	}
	
	PEM_read_PUBKEY(fp, &pkey, NULL, NULL);   
	if (pkey == NULL) {
		fprintf(stderr, "erreur: PEM_read_PUBKEY\n");
		return NULL;
	}

	fclose(fp);
	return pkey; 
}

/* Convertit une clé publique PEM en EVP_PKEY */
EVP_PKEY *convert_private_key_to_evp_pkey(char *privkey) {
	EVP_PKEY *pkey = NULL;
	FILE *fp = fopen(privkey, "r");
	if(fp == NULL){
		perror("fopen");
		return NULL;
	}
	
	PEM_read_PrivateKey(fp, &pkey, NULL, NULL);    
	if (pkey == NULL) {
		fprintf(stderr, "erreur: PEM_read_PrivateKey\n");
		return NULL;
	}

	fclose(fp);
	return pkey; 
}

int lire_cle_publique_pem(const char *chemin, unsigned char cle[113]) {
    FILE *f = fopen(chemin, "r");
    if (!f) {
        perror("fopen");
        return -1;
    }
    size_t offset = 0;
    char ligne[128];
    while (fgets(ligne, sizeof(ligne), f)) {
        size_t len = strlen(ligne);
        // Copie chaque ligne dans cle (y compris \n)
        if (offset + len > 113) len = 113 - offset;
        memcpy(cle + offset, ligne, len);
        offset += len;
        if (offset >= 113) break;
    }
    fclose(f);
    if (offset != 113) {
        fprintf(stderr, "Erreur : la clé ne fait pas 113 octets (lu %zu)\n", offset);
        return -1;
    }
    return 0;
}

// Convertit une clé publique PEM (dans un buffer) en EVP_PKEY*
EVP_PKEY *cle_publique_buffer_to_evp(const char *cle, size_t len) {
    BIO *mem = BIO_new_mem_buf(cle, len);
    if (!mem) return NULL;
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(mem, NULL, NULL, NULL);
    BIO_free(mem);
    return pkey;
}

/* Génère une paire de clés ED25519 */
int generate_ed25519_key(char* public_key_name, char* private_key_name){
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
	int ret = 0;
	FILE *bp_public = NULL;
	FILE* bp_private = NULL;

	// initialise le contexte pour la génération d'une paire de clés
	if(EVP_PKEY_keygen_init(pctx) <= 0){
		fprintf(stderr, "erreur EVP_PKEY_keygen_init\n");
		return ret;
	}

	// engendre une paire de clés ED25519
	EVP_PKEY_generate(pctx, &pkey);
	if(pkey == NULL) {
		fprintf(stderr, "erreur EVP_PKEY_keygen\n");
		goto err;
	}

	// sauvegarde la clé publique
	bp_public = fopen(public_key_name, "w+");
	ret = PEM_write_PUBKEY(bp_public, pkey);
	fclose(bp_public);
	if(ret != 1){
		fprintf(stderr, "erreur PEM_write_PUBKEY\n");
		goto err;
	}
	
	// sauvegarde la clé privée 
	bp_private = fopen(private_key_name, "w+");
	ret = PEM_write_PrivateKey(bp_private, pkey, NULL, NULL, 0, NULL, NULL);
	fclose(bp_private);
	if(ret != 1){
		fprintf(stderr, "PEM_write_PrivateKey error\n");
		goto err;
	}

	ret = 1;

 err:
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pctx);
	return ret;
}

/* Signature (ED25519) */
int sign(EVP_PKEY *pkey, unsigned char *msg, unsigned char **sig, size_t *slen) {
	EVP_MD_CTX *mdctx = NULL;
	int ret = 0, msg_len = strlen((char *) msg);
	
	*sig = NULL;

	/* crée le Message Digest Context */
	if(!(mdctx = EVP_MD_CTX_create())){
		fprintf(stderr, "erreur EVP_MD_CTX_create\n");
		goto err;
	}

	/* initialise l'operation DigestSign (hachage avec signature) 
	 * avec la clé privée.
	 * 3eme param (fonction de hachage) doit être NULL pour une clé ED25519
	 * puisque celle-ci utilise SHA-512 (pas de choix) 
	 * si RSA, fonction de hachage peut être EVP_sha256() */
	if(1 != EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey)){
		fprintf(stderr, "erreur EVP_DigestSignInit\n");
		goto err;
	} 
	
	/* appel une 1ère fois de EVP_DigestSign avec le paramètre 
	 * sig à NULL afin d'obtenir la longueur de la signature */
	if(1 != EVP_DigestSign(mdctx, NULL, slen, msg, msg_len)) {
		fprintf(stderr, "erreur EVP_DigestSign\n");
		goto err;
	} 

	/* alloue la mémoire pour la signature */ 
	if(!(*sig = malloc(sizeof(unsigned char) * (*slen)))) {
		fprintf(stderr, "erreur malloc\n");
		goto err;
	} 

	/* obtention de la signature */
	if(1 != EVP_DigestSign(mdctx, *sig, slen, msg, msg_len)) {
		fprintf(stderr, "erreur EVP_DigestSign\n");
		goto err;
	} 

	/* Succès */
	ret = 1;
	printf("message : %s\n", msg);
	EVP_MD_CTX_free(mdctx);
	return 1;
 
 err:
	if(ret != 1)
		fprintf(stderr, "erreur dans sign()\n");
		 
	/* nettoyage mémoire */
	if(*sig && !ret) OPENSSL_free(*sig); // = free(*sig);
	if(mdctx) EVP_MD_CTX_free(mdctx); //EVP_MD_CTX_destroy(mdctx);

	return 0;
}

/* fonctionne pour clés RSA et ED25519 */
int verify(EVP_PKEY *pubkey, unsigned char *msg, unsigned char *sig, size_t slen) {
	EVP_MD_CTX *mdctx;
	int ret = -1;
	
	/* crée le Message Digest Context */
	if(!(mdctx = EVP_MD_CTX_create()))  return 0; //erreur

	/* initialise l'operation DigestVerify (hachage avec signature) 
	 * avec la clé publique 
	 * 3eme param (fonction de hachage) doit être NULL pour une clé ED25519
	 * puisque celle-ci utilise SHA-512 (pas de choix)
	 * si RSA, fonction de hachage peut être EVP_sha256() */
	if(1 != EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pubkey)) {
		fprintf(stderr, "erreur EVP_DigestVerifyInit : %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto err;
	}

	if(1 == EVP_DigestVerify(mdctx, sig, slen, msg, strlen((char *) msg)))
		printf("signature ok\n");
	else {
		printf("document corrompu\n");
		return 0;
	}

	ret = 1;
 err:
	EVP_MD_CTX_free(mdctx);
	
	return ret;
}


// Génère un certificat auto-signé à partir d'une clé privée PEM
int generer_certificat_autosigne(const char *keyfile, const char *certfile, const char *common_name) {
    FILE *fp = fopen(keyfile, "r");
    if (!fp) {
        fprintf(stderr, "Erreur ouverture clé privée : %s\n", keyfile);
        return 0;
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) {
        fprintf(stderr, "Erreur lecture clé privée\n");
        return 0;
    }

    X509 *x509 = X509_new();
    if (!x509) {
        EVP_PKEY_free(pkey);
        return 0;
    }
    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); // 1 an

    X509_set_pubkey(x509, pkey);

    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)common_name, -1, -1, 0);
    X509_set_issuer_name(x509, name);

    if (!X509_sign(x509, pkey, NULL)) {
        fprintf(stderr, "Erreur signature certificat\n");
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return 0;
    }

    fp = fopen(certfile, "wb");
    if (!fp) {
        fprintf(stderr, "Erreur création fichier certificat : %s\n", certfile);
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return 0;
    }
    PEM_write_X509(fp, x509);
    fclose(fp);

    X509_free(x509);
    EVP_PKEY_free(pkey);
    return 1;
}

void init_superviseur()
{
	SSL_library_init();
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
