#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sodium.h>
#include <string.h>
#include <arpa/inet.h> // Pour htonl et htons

#include "../include/message.h"

// // Définition du message "Quitter le système d’enchères"
// typedef struct {
//     uint8_t CODE;   // Code du message (13)
//     uint16_t ID;    // Identifiant du pair (2 octets, big-endian)
// } QuitMessage;

// typedef struct {
//     uint8_t CODE;   // Code du message (13)
//     uint16_t ID;    // Identifiant du pair (2 octets, big-endian)
//     uint32_t NUMV;  // Numéro de la vente (4 octets)
//     uint32_t PRIX;  // Prix proposé (4 octets)
// } RejetMessage;

// typedef struct {
//     uint8_t CODE;   // Code du message (16, 17 ou 18)
//     uint16_t ID;    // Identifiant du pair
//     uint32_t NUMV;  // Numéro de la vente (uniquement si CODE = 16 ou 17)
// } DisparitionSuperviseurMessage;

// typedef struct {
//     uint8_t CODE;   // Code du message (18)
//     uint16_t ID;    // Identifiant du pair qui envoie le message
//     uint16_t NB;    // Nombre de pairs disparus
//     uint16_t ids[]; // Liste des identifiants des pairs disparus (taille dynamique)
// } DisparitionPairsMessage;

// typedef struct {
//     uint8_t CODE;
//     uint16_t ID;   // Identifiant du superviseur
//     uint32_t NUMV; // Numéro de la vente
//     uint32_t PRIX; // Prix de la dernière enchère ou prix initial
// } FinalisationVenteMessage;

// typedef struct {
//     uint8_t CODE;
//     uint16_t ID;   // Identifiant du superviseur
//     uint32_t NUMV; // Numéro de la vente
//     uint32_t PRIX; // Prix de la dernière enchère ou prix initial
// } VenteMessage;

// // Structure pour le message de validation
// typedef struct {
//     uint8_t code;            // Code de validation (1)
//     uint16_t id;             // Identifiant du pair
//     unsigned char signature[crypto_sign_BYTES]; // Signature du message
// } ValidationMessage;

// typedef struct {
//     int id;
//     unsigned char message[256];
//     unsigned char signature[crypto_sign_BYTES];
// } SignedMessage;

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
    //quand on fait apelle a la fonction on met 14 ou 15, CODE vaut 14 si l’enchère est rejetée car en concurrence avec une autre enchère et 15 sinon
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




// int main() {
//     QuitMessage msg;
//     msg.CODE = 13;
//     msg.ID = htons(42); // Exemple d'ID (42)

//     // Affichage en hexadécimal pour vérification
//     printf("Message (hex) : %02X %04X\n", msg.CODE, ntohs(msg.ID));

//     // Exemple : rejet d'une enchère de l'utilisateur 42 sur la vente 1234 avec un prix de 500€
//     RejetMessage msg1;
//     msg1.CODE = 14;           // 14 : rejet pour concurrence
//     msg1.ID = htons(42);      // ID du pair
//     msg1.NUMV = htonl(1234);  // Numéro de la vente
//     msg1.PRIX = htonl(500);   // Prix proposé

//     // Affichage en hexadécimal pour vérifier le format
//     printf("Message (hex) : %02X %04X %08X %08X\n", msg1.CODE, ntohs(msg1.ID), ntohl(msg1.NUMV), ntohl(msg1.PRIX));


//     return 0;
// }