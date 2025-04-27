//message.c

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h> // Pour htonl et htons

#include "../include/message.h"
#include "../include/peer.h"

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>  // pour close()
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>  // Pour les fonctions de conversion de réseau



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


// Fonction pour parser un message en fonction du code
int parse_message(uint8_t *msg, size_t msg_len, struct message *msg_struct) {
    size_t offset = 0;

    if (msg == NULL || msg_struct == NULL) {
        fprintf(stderr, "Erreur : pointeurs invalides.\n");
        return -1;
    }

    // Vérifier la longueur minimale pour le code et ID
    if (msg_len < 3) {
        fprintf(stderr, "Message trop court.\n");
        return -1;
    }

    // Lire le code (1 octet)
    msg_struct->code = msg[offset++];
    
    // Lire l'ID (2 octets)
    if (msg_len < offset + 2) {
        fprintf(stderr, "Message trop court pour l'ID.\n");
        return -1;
    }
    msg_struct->id = ntohs(*(uint16_t*)&msg[offset]);
    offset += 2;

    // Selon le code, lire les champs appropriés
    switch (msg_struct->code) {
        

        case 3:  // CODE = 3
            // Pas de champs supplémentaires à lire, juste le code.
            break;

        case 4:  // CODE = 4
            // Lire l'adresse IP (16 octets)
            if (msg_len >= offset + 16) {
                memcpy(&msg_struct->ip, &msg[offset], 16);
                offset += 16;
            } else {
                fprintf(stderr, "Message trop court pour l'adresse IP.\n");
                return -1;
            }
            
            // Lire le port (2 octets)
            if (msg_len >= offset + 2) {
                msg_struct->port = ntohs(*(uint16_t*)&msg[offset]);
                offset += 2;
            } else {
                fprintf(stderr, "Message trop court pour le port.\n");
                return -1;
            }
            break;

        case 5:  // CODE = 5
            // Lire l'info (INFO)
            // Lire l'ID (2 octets)
            if (msg_len >= offset + 2) {
                msg_struct->id = ntohs(*(uint16_t*)&msg[offset]);
                offset += 2;
            } else {
                fprintf(stderr, "Message trop court pour l'ID.\n");
                return -1;
            }
            
            // Lire l'adresse IP (16 octets)
            if (msg_len >= offset + 16) {
                memcpy(&msg_struct->ip, &msg[offset], 16);
                offset += 16;
            } else {
                fprintf(stderr, "Message trop court pour l'adresse IP.\n");
                return -1;
            }

            // Lire le port (2 octets)
            if (msg_len >= offset + 2) {
                msg_struct->port = ntohs(*(uint16_t*)&msg[offset]);
                offset += 2;
            } else {
                fprintf(stderr, "Message trop court pour le port.\n");
                return -1;
            }

            // Lire la clé (CLE)
            // Par exemple, la clé pourrait être une chaîne de caractères de longueur variable
            // if (msg_len >= offset + 1) {
            //     uint8_t cle_len = msg[offset++];
            //     if (msg_len >= offset + cle_len) {
            //         memcpy(msg_struct->cle, &msg[offset], cle_len);
            //         msg_struct->cle[cle_len] = '\0';  // Terminer la chaîne de caractères
            //         offset += cle_len;
            //     } else {
            //         fprintf(stderr, "Message trop court pour la clé.\n");
            //         return -1;
            //     }
            // }
            break;

        case 50:  // CODE = 50
        case 51:  // CODE = 51
            // Pas de champs supplémentaires pour ces codes
            break;

        default:
            fprintf(stderr, "Code inconnu : %d\n", msg_struct->code);
            return -1;
    }

    return 0;
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