//message.c

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h> // Pour htonl et htons
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "../include/message.h"
#include "../include/peer.h"
#include "../include/superviseur.h"

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>  // pour close()
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>  // Pour les fonctions de conversion de réseau

#include "../include/peer.h"

// --------------------------- CODE 4 -----------------------------------------------
int msg_4 (uint8_t *msg, uint16_t id_peer, uint16_t port_tcp) {
    // 1 octect pour le code
    // 2 octets pour l'ID du pair
    // 16 octets pour l'adresse perso
    // 2 octets pour le port TCP
    uint8_t code = 4;
    struct in6_addr adresse_perso;

    // Récupérer l'adresse perso
    if (get_adresse_perso_par_index(&adresse_perso, global_iface_index) != 0) {
        fprintf(stderr, "Erreur pour récupérer l'adresse perso\n");
        return -1;
    }

    // Construction du message
    msg[0] = code;
    
    uint16_t id_net = htons(id_peer);    // Convertir en format réseau
    uint16_t port_net = htons(port_tcp); // Convertir en format réseau

    memcpy(&msg[1], &id_net, 2);           // ID du pair
    memcpy(&msg[3], &adresse_perso, 16);   // Adresse IP
    memcpy(&msg[19], &port_net, 2);        // Port

    return 0;
}

// Parse du message de code 4
int parse_msg_4 (uint8_t *msg, size_t msg_len, struct message_4 *msg_struct) {
    if (!msg || !msg_struct || msg_len < 21) return -1;

    msg_struct->code = msg[0];
    if (msg_struct->code != 4) {
        fprintf(stderr, "Erreur : seul le code 4 est pris en charge.\n");
        return -1;
    }

    msg_struct->id = ntohs(*(uint16_t*)&msg[1]);
    memcpy(&msg_struct->ip, &msg[3], 16);
    msg_struct->port = ntohs(*(uint16_t*)&msg[19]);

    return 0;
}


// --------------------------- CODE 5 -----------------------------------------------

int msg_5(uint8_t *msg, uint16_t id_peer, uint16_t port_tcp, unsigned char *public_key) {
    struct in6_addr ip;
    size_t offset = 0;
    msg[offset++] = 5;  // CODE = 5

    // ID (big endian)
    msg[offset++] = (id_peer >> 8) & 0xFF;
    msg[offset++] = id_peer & 0xFF;

    // IP (16 octets)
    memcpy(msg + offset, &ip, 16);
    offset += 16;

    // PORT (big endian)
    msg[offset++] = (port_tcp >> 8) & 0xFF;
    msg[offset++] = port_tcp & 0xFF;

    // CLE PUBLIQUE (113 octets)
    memcpy(msg + offset, public_key, ED25519_KEY_WITH_HEADER_SIZE);
    offset += ED25519_KEY_WITH_HEADER_SIZE;

    return offset;  // taille totale écrite
}

int parse_msg_5(uint8_t *msg, size_t msg_len, struct message_5 *msg_struct) {
    if (msg_len < 1 + 2 + 16 + 2 + ED25519_KEY_WITH_HEADER_SIZE)
        return -1;  // message trop court

    size_t offset = 0;

    msg_struct->code = msg[offset++];

    msg_struct->id = (msg[offset] << 8) | msg[offset + 1];
    offset += 2;

    memcpy(&msg_struct->ip, msg + offset, 16);
    offset += 16;

    msg_struct->port = (msg[offset] << 8) | msg[offset + 1];
    offset += 2;

    memcpy(msg_struct->cle, msg + offset, ED25519_KEY_WITH_HEADER_SIZE);
    offset += ED25519_KEY_WITH_HEADER_SIZE;

    return 0;
}


// --------------------------- CODE 50 -----------------------------------------------
int msg_50(uint8_t *msg) {
    msg[0] = 50;  // CODE = 50
    return 1;  // taille totale écrite
}

int parse_msg_50(uint8_t *msg, size_t msg_len, struct message_50 *msg_struct) {
    if (msg_len < 1) return -1;  // message trop court

    msg_struct->code = msg[0];
    if (msg_struct->code != 50) return -1;
    return 0;
}

// --------------------------- CODE 51 -----------------------------------------------
int msg_51(uint8_t *msg, uint16_t id) {
    msg[0] = 51;  // CODE = 51
    msg[1] = (id >> 8) & 0xFF;
    msg[2] = id & 0xFF;
    return 3;  // taille totale écrite
}

int parse_msg_51(uint8_t *msg, size_t msg_len, struct message_51 *msg_struct) {
    if (msg_len < 3) return -1;  // message trop court

    msg_struct->code = msg[0];
    if (msg_struct->code != 51) return -1;

    msg_struct->id = (msg[1] << 8) | msg[2];
    return 0;
}

int msg_8(uint8_t *msg, uint16_t id,uint32_t numv,uint32_t prix) {
    msg[0] = 8;  // Code du message

    // ID (2 octets, réseau)
    uint16_t net_id = htons(id);
    memcpy(&msg[1], &net_id, sizeof(net_id));

    // numv (4 octets, réseau)
    uint32_t net_numv = htonl(numv);
    memcpy(&msg[3], &net_numv, sizeof(net_numv));

    // prix (4 octets, réseau)
    uint32_t net_prix = htonl(prix);
    memcpy(&msg[7], &net_prix, sizeof(net_prix));

    return 11;  // Taille totale du message
}

void envoyer_message(int socket, uint16_t id) {
    QuitMessage msg;
    msg.CODE = 13;  // Code du message de fin
    msg.ID = htons(id); // Conversion en big-endian

    // Envoi du message
    send(socket, &msg, sizeof(msg), 0);
}

// Fonction pour envoyer le message
void envoyer_rejet(int socket, uint8_t code, uint16_t id, uint32_t numv, uint32_t prix) {
    RejetMessage msg;
    msg.CODE = code;         // 14 ou 15
    //quand on fait apelle a la fonction on met 14 ou 15, CODE vaut 14 si l'enchère est rejetée car en concurrence avec une autre enchère et 15 sinon
    msg.ID = htons(id);      // Conversion en big-endian
    msg.NUMV = htonl(numv);  // Conversion en big-endian
    msg.PRIX = htonl(prix);  // Conversion en big-endian

    // Envoi du message
    send(socket, &msg, sizeof(msg), 0);
}

void envoyer_vente(int socket,bool etape, uint16_t id, uint32_t numv, uint32_t prix) {
    FinalisationVenteMessage msg;
    if(etape==true){//true pour initier false pour enrichier
        msg.CODE = 8; //supeviseur
    }else{
        msg.CODE = 9;//
    }
    //la gestion de l'id dans l'appel 
    //faire verif si on est true le code doit etre 8 et c'est oblige superviseur
    //pour la cloture soit superviseur si personne la prend ou gagnant si reuss
    msg.ID = htons(id);      
    msg.NUMV = htonl(numv);  
    msg.PRIX = htonl(prix);  

   
    send(socket, &msg, sizeof(msg), 0);
}

void envoyer_finalisation_vente(int socket,bool etape, uint16_t id, uint32_t numv, uint32_t prix) {
    FinalisationVenteMessage msg;
    if(etape==true){//true pour cloture false pour finalisation
        msg.CODE = 11; 
    }else{
        msg.CODE = 12;
    }
    //la gestion de l'id dans l'appel 
    //faire verif si on est true le code doit etre 11 et c'est oblige superviseur
    //pour la cloture soit superviseur si personne la prend ou gagnant si reuss
    msg.ID = htons(id);      
    msg.NUMV = htonl(numv);  
    msg.PRIX = htonl(prix);  

    send(socket, &msg, sizeof(msg), 0);
}

void envoyer_disparition(int socket, bool superviseur, uint16_t id, uint32_t numv, uint16_t *ids_disparus, uint16_t nb) {
    if (superviseur) {
        // Cas d'un superviseur disparu (CODE = 16 ou 17)
        DisparitionSuperviseurMessage msg;
        msg.CODE = 16;  // Par défaut, CODE = 16 (annulation d'une vente)
        msg.ID = htons(id);
        msg.NUMV = htonl(numv);

        // Envoi du message
        send(socket, &msg, sizeof(msg), 0);
    } else {
        // Cas de disparition de pairs non superviseurs (CODE = 18)
        size_t taille_msg = sizeof(DisparitionPairsMessage) + nb * sizeof(uint16_t);
        DisparitionPairsMessage *msg = malloc(taille_msg);
        if (!msg) {
            perror("Erreur d'allocation mémoire");
            return;
        }

        msg->CODE = 18;
        msg->ID = htons(id);
        msg->NB = htons(nb);

        // Ajouter les identifiants des pairs disparus
        for (int i = 0; i < nb; i++) {
            msg->ids[i] = htons(ids_disparus[i]);
        }

        // Envoi du message
        send(socket, msg, taille_msg, 0);
        free(msg);
    }
}

void envoyer_enchere(int socket, uint16_t id, uint32_t numv, uint32_t prix) {
    VenteMessage msg;
    msg.CODE = 10; // Code d'enchère
    msg.ID = htons(id);
    msg.NUMV = htonl(numv);
    msg.PRIX = htonl(prix);
    send(socket, &msg, sizeof(msg), 0);
}

// Format ED25519 public key with header and trailer texts
int format_ed25519_public_key(unsigned char *cle, EVP_PKEY *pubkey) {
    // Header text: "-----BEGIN PUBLIC KEY-----\n"
    const char *header = "-----BEGIN PUBLIC KEY-----\n";
    memcpy(cle, header, strlen(header));
    size_t offset = strlen(header);

    // Get raw public key bytes
    unsigned char raw_key[32];
    size_t raw_len = sizeof(raw_key);
    if (EVP_PKEY_get_raw_public_key(pubkey, raw_key, &raw_len) != 1) {
        fprintf(stderr, "Error getting raw public key\n");
        return -1;
    }

    // Base64 encode the raw key
    char base64_key[45];
    int base64_len = EVP_EncodeBlock((unsigned char *)base64_key, raw_key, raw_len);
    if (base64_len < 0) {
        fprintf(stderr, "Error base64 encoding public key\n");
        return -1;
    }

    // Copy base64 encoded key
    memcpy(cle + offset, base64_key, base64_len);
    offset += base64_len;

    // Trailer text: "\n-----END PUBLIC KEY-----\n"
    const char *trailer = "\n-----END PUBLIC KEY-----\n";
    memcpy(cle + offset, trailer, strlen(trailer));
    offset += strlen(trailer);

    // Ensure we have exactly 113 bytes
    if (offset != 113) {
        fprintf(stderr, "Error: formatted key length is %zu, expected 113\n", offset);
        return -1;
    }

    return 0;
}

// --------------------------- CODE 6 -----------------------------------------------
int msg_6(uint8_t *msg, uint16_t id_peer, struct in6_addr ip, uint16_t port_tcp, unsigned char *cle) {
    size_t offset = 0;
    msg[offset++] = 6;  // CODE = 6

    // ID (big endian)
    msg[offset++] = (id_peer >> 8) & 0xFF;
    msg[offset++] = id_peer & 0xFF;

    // IP (16 octets)
    memcpy(msg + offset, &ip, 16);
    offset += 16;

    // PORT (big endian)
    msg[offset++] = (port_tcp >> 8) & 0xFF;
    msg[offset++] = port_tcp & 0xFF;

    // CLE PUBLIQUE (113 octets)
    memcpy(msg + offset, cle, 113);
    offset += 113;

    return offset;  // taille totale écrite
}

int parse_msg_6(uint8_t *msg, size_t msg_len, struct message_6 *msg_struct) {
    if (msg_len < 1 + 2 + 16 + 2 + 113)
        return -1;  // message trop court

    size_t offset = 0;

    msg_struct->code = msg[offset++];
    if (msg_struct->code != 6) return -1;

    msg_struct->id = (msg[offset] << 8) | msg[offset + 1];
    offset += 2;

    memcpy(&msg_struct->ip, msg + offset, 16);
    offset += 16;

    msg_struct->port = (msg[offset] << 8) | msg[offset + 1];
    offset += 2;

    memcpy(msg_struct->cle, msg + offset, 113);
    offset += 113;

    return 0;
}

// --------------------------- CODE 7 -----------------------------------------------
int msg_7(uint8_t *msg, uint16_t id, uint32_t numv, uint32_t prix, 
          const unsigned char *message, size_t message_len,
          const unsigned char *signature, size_t sig_len) {
    if (!msg || !message || !signature || message_len > 256 || sig_len != ED25519_SIGNATURE_SIZE)
        return -1;

    size_t offset = 0;
    msg[offset++] = 7;  // CODE = 7

    // ID (big endian)
    msg[offset++] = (id >> 8) & 0xFF;
    msg[offset++] = id & 0xFF;

    // NUMV (big endian)
    msg[offset++] = (numv >> 24) & 0xFF;
    msg[offset++] = (numv >> 16) & 0xFF;
    msg[offset++] = (numv >> 8) & 0xFF;
    msg[offset++] = numv & 0xFF;

    // PRIX (big endian)
    msg[offset++] = (prix >> 24) & 0xFF;
    msg[offset++] = (prix >> 16) & 0xFF;
    msg[offset++] = (prix >> 8) & 0xFF;
    msg[offset++] = prix & 0xFF;

    // LMESS
    msg[offset++] = (uint8_t)message_len;

    // MESS
    memcpy(msg + offset, message, message_len);
    offset += message_len;

    // LSIG
    msg[offset++] = (uint8_t)sig_len;

    // SIG
    memcpy(msg + offset, signature, sig_len);
    offset += sig_len;

    return offset;  // taille totale écrite
}

int parse_msg_7(uint8_t *msg, size_t msg_len, EnchereMessage *msg_struct) {
    if (!msg || !msg_struct || msg_len < 1 + 2 + 4 + 4 + 1 + 1 + ED25519_SIGNATURE_SIZE)
        return -1;

    size_t offset = 0;

    msg_struct->code = msg[offset++];
    if (msg_struct->code != 7) return -1;

    // ID
    msg_struct->id = (msg[offset] << 8) | msg[offset + 1];
    offset += 2;

    // NUMV
    msg_struct->numv = (msg[offset] << 24) | (msg[offset + 1] << 16) | 
                      (msg[offset + 2] << 8) | msg[offset + 3];
    offset += 4;

    // PRIX
    msg_struct->prix = (msg[offset] << 24) | (msg[offset + 1] << 16) | 
                      (msg[offset + 2] << 8) | msg[offset + 3];
    offset += 4;

    // LMESS
    msg_struct->lmess = msg[offset++];

    // MESS
    if (msg_struct->lmess > 0) {
        memcpy(msg_struct->message, msg + offset, msg_struct->lmess);
    }
    offset += msg_struct->lmess;

    // LSIG
    msg_struct->lsig = msg[offset++];
    if (msg_struct->lsig != ED25519_SIGNATURE_SIZE) return -1;

    // SIG
    memcpy(msg_struct->signature, msg + offset, msg_struct->lsig);
    offset += msg_struct->lsig;

    return 0;
}

void envoyer_info_auction(int socket, uint16_t id, uint32_t numv, uint32_t prix, 
                         const unsigned char *message, size_t message_len,
                         const unsigned char *signature) {
    uint8_t msg[1 + 2 + 4 + 4 + 1 + 256 + 1 + ED25519_SIGNATURE_SIZE]; // Maximum size
    int msg_len = msg_7(msg, id, numv, prix, message, message_len, signature, ED25519_SIGNATURE_SIZE);
    if (msg_len > 0) {
        send(socket, msg, msg_len, 0);
    }
}