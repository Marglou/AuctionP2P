// message.c
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h> 
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <unistd.h> 
#include <netinet/in.h> 

#include "../include/message.h"
#include "../include/peer.h"
#include "../include/superviseur.h"
#include "../include/enchere.h"
#include "../include/connexion.h"
#include "../include/utils.h"
#include "../include/securite.h"


// --------------------------- CODE 4 -----------------------------------------------
int msg_4(uint8_t *msg, uint16_t id_peer, uint16_t port_tcp) {
    // 1 octect pour le code
    // 2 octets pour l'ID du pair
    // 16 octets pour l'adresse perso
    // 2 octets pour le port TCP
    uint8_t code = 4;
    struct in6_addr adresse_perso;

    // Récupérer l'adresse perso
    if (get_adresse_perso_par_index(&adresse_perso, p.global_iface_index) != 0)
    {
        fprintf(stderr, "Erreur pour récupérer l'adresse perso\n");
        return -1;
    }

    msg[0] = code;

    uint16_t id_net = htons(id_peer);    
    uint16_t port_net = htons(port_tcp); 

    memcpy(&msg[1], &id_net, 2);         // ID du pair
    memcpy(&msg[3], &adresse_perso, 16); // Adresse IP
    memcpy(&msg[19], &port_net, 2);      // Port

    return 0;
}

int get_adresse_perso_from_socket(int sock, struct in6_addr *addr) {
    if (!addr) {
        fprintf(stderr, "Erreur : pointeur d'adresse invalide.\n");
        return -1;
    }

    struct sockaddr_in6 local_addr;
    socklen_t addr_len = sizeof(local_addr);

    if (getsockname(sock, (struct sockaddr *)&local_addr, &addr_len) < 0) {
        perror("getsockname");
        return -1;
    }

    if (local_addr.sin6_family != AF_INET6) {
        fprintf(stderr, "Erreur : la socket n'est pas de type IPv6.\n");
        return -1;
    }

    memcpy(addr, &local_addr.sin6_addr, sizeof(struct in6_addr));
    return 0;
}

// Parse du message de code 4
int parse_msg_4(uint8_t *msg, size_t msg_len, struct message_4 *msg_struct)
{
    if (!msg || !msg_struct || msg_len < 21)
        return -1;

    msg_struct->code = msg[0];
    if (msg_struct->code != 4)
    {
        fprintf(stderr, "Erreur : seul le code 4 est pris en charge.\n");
        return -1;
    }

    msg_struct->id = ntohs(*(uint16_t *)&msg[1]);
    memcpy(&msg_struct->ip, &msg[3], 16);
    msg_struct->port = ntohs(*(uint16_t *)&msg[19]);

    return 0;
}

// --------------------------- CODE 5 -----------------------------------------------

int msg_5(uint8_t *msg, uint16_t id_peer, uint16_t port_tcp, struct in6_addr ip, unsigned char *public_key)
{
    size_t offset = 0;
    msg[offset++] = 5; 

    msg[offset++] = (id_peer >> 8) & 0xFF;
    msg[offset++] = id_peer & 0xFF;

    memcpy(msg + offset, &ip, 16);
    offset += 16;

    msg[offset++] = (port_tcp >> 8) & 0xFF;
    msg[offset++] = port_tcp & 0xFF;

    memcpy(msg + offset, public_key, ED25519_KEY_WITH_HEADER_SIZE);
    offset += ED25519_KEY_WITH_HEADER_SIZE;

    return offset; 
}

int parse_msg_5(uint8_t *msg, size_t msg_len, struct message_5 *msg_struct)
{
    if (msg_len < 1 + 2 + 16 + 2 + ED25519_KEY_WITH_HEADER_SIZE)
        return -1; // message trop court

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
int msg_50(uint8_t *msg)
{
    msg[0] = 50; 
    return 1;    
}

int parse_msg_50(uint8_t *msg, size_t msg_len, struct message_50 *msg_struct)
{
    if (msg_len < 1)
        return -1; 

    msg_struct->code = msg[0];
    if (msg_struct->code != 50)
        return -1;
    return 0;
}

// --------------------------- CODE 51 -----------------------------------------------
int msg_51(uint8_t *msg, uint16_t id)
{
    msg[0] = 51; 
    msg[1] = (id >> 8) & 0xFF;
    msg[2] = id & 0xFF;
    return 3; 
}

int parse_msg_51(uint8_t *msg, size_t msg_len, struct message_51 *msg_struct)
{
    if (msg_len < 3)
        return -1; 

    msg_struct->code = msg[0];
    if (msg_struct->code != 51)
        return -1;

    msg_struct->id = (msg[1] << 8) | msg[2];
    return 0;
}

int msg_8_9_10(uint8_t *msg, uint8_t code, uint16_t id, uint32_t numv, uint32_t prix) {
    if (!msg) return -1;
    
    if (code != 8 && code != 9 && code != 10) return -1;
    
    msg[0] = code; // Message code (8, 9, or 10)
    
    uint16_t id_net = htons(id);
    memcpy(&msg[1], &id_net, sizeof(id_net));
    
    uint32_t numv_net = htonl(numv);
    memcpy(&msg[3], &numv_net, sizeof(numv_net));
    
    uint32_t prix_net = htonl(prix);
    memcpy(&msg[7], &prix_net, sizeof(prix_net));
    
    return 11; 
}

// ---------------  CODE 13 ------------------------------------------------
int msg_13(uint8_t *msg, uint16_t id)
{
    msg[0] = 13; 
    msg[1] = (id >> 8) & 0xFF;
    msg[2] = id & 0xFF;
    return 3; 
}

int parse_msg_13(uint8_t *msg, size_t msg_len, struct message_13 *msg_struct)
{
    if (msg_len < 3)
        return -1; 

    msg_struct->code = msg[0];
    if (msg_struct->code != 13)
        return -1;

    msg_struct->id = (msg[1] << 8) | msg[2];
    return 0;
}


int msg_14_15(uint8_t *msg, uint8_t code, uint16_t id, uint32_t numv, uint32_t prix) {
    if (!msg) return -1;
    
    if (code != 14 && code != 15) return -1;
    
    msg[0] = code; // Message code (14 or 15)
    
    uint16_t id_net = htons(id);
    memcpy(&msg[1], &id_net, sizeof(id_net));
    
    uint32_t numv_net = htonl(numv);
    memcpy(&msg[3], &numv_net, sizeof(numv_net));
    
    uint32_t prix_net = htonl(prix);
    memcpy(&msg[7], &prix_net, sizeof(prix_net));
    
    return 11; 
}

// Function to parse auction messages (8, 9, 10)
int parse_msg_8_9_10(uint8_t *msg, size_t msg_len, struct message_8 *msg_struct) {
    if (!msg || !msg_struct || msg_len < 11) return -1;
    
    msg_struct->code = msg[0];
    if (msg_struct->code != 8 && msg_struct->code != 9 && msg_struct->code != 10) return -1;
    
    uint16_t id_net;
    memcpy(&id_net, &msg[1], sizeof(id_net));
    msg_struct->id = ntohs(id_net);
    
    uint32_t numv_net;
    memcpy(&numv_net, &msg[3], sizeof(numv_net));
    msg_struct->numv = ntohl(numv_net);
    
    uint32_t prix_net;
    memcpy(&prix_net, &msg[7], sizeof(prix_net));
    msg_struct->prix = ntohl(prix_net);
    
    return 0;
}

// ---------------  CODE 1 ------------------------------------------------
// Renvoie la taille totale du message écrit dans msg, ou -1 en cas d'erreur
int msg_1(uint8_t *msg, uint16_t id, char *mess, uint8_t *sig, uint8_t siglen) {
    uint8_t codemsg = 1;
    uint8_t lmess = (uint8_t)strlen(mess);

    if (lmess > 255 || siglen > 255) return -1;  

    uint16_t net_id = htons(id);
    size_t offset = 0;

    msg[offset++] = codemsg;

    memcpy(msg + offset, &net_id, sizeof(net_id));
    offset += sizeof(net_id);

    msg[offset++] = lmess;

    memcpy(msg + offset, mess, lmess);
    offset += lmess;

    msg[offset++] = siglen;

    if (siglen > 0) {
        memcpy(msg + offset, sig, siglen);
        offset += siglen;
    }

    return (int)offset;  
}

int parse_msg_1(const uint8_t *buf, size_t len, struct message_1 *msg) {

    if (len < 3) return -1; // Minimum : CODE + ID(2) + LMESS + LSIG

    size_t offset = 0;

    uint8_t code = buf[offset++];
    if (code != 1) return -2;

    msg->id = ntohs(*(uint16_t *)(buf + offset));
    offset += 2;

    msg->lmess = buf[offset++];
    if (msg->lmess > 255 || offset + msg->lmess + 1 > len)
        return -3;

    memcpy(msg->mess, buf + offset, msg->lmess);
    msg->mess[msg->lmess] = '\0';
    offset += msg->lmess;

    // printf("DEBUG: lsig=%u, offset=%zu, len=%zu\n", msg->lsig, offset, len);
    msg->lsig = buf[offset++];
    if (msg->lsig > ED25519_SIGNATURE_SIZE || offset + msg->lsig > len)
        return -4;

    if (msg->lsig > 0)
        memcpy(msg->sig, buf + offset, msg->lsig);

    return 0;
}


// ---------------------------------- CODE 2   -------------------------------------------

int msg_2(uint8_t *msg, uint16_t id, char *mess, uint8_t *sig, uint8_t siglen, uint16_t nb_validations,
          uint16_t *ids, uint8_t *siglens, unsigned char **sigs) {
    uint8_t codemsg = 2;
    uint8_t lmess = (uint8_t)strlen(mess);

    if (lmess > 255 || siglen > 255) return -1;

    uint16_t net_id = htons(id);
    size_t offset = 0;

    msg[offset++] = codemsg;
    memcpy(msg + offset, &net_id, sizeof(net_id));
    offset += sizeof(net_id);
    msg[offset++] = lmess;
    memcpy(msg + offset, mess, lmess);
    offset += lmess;
    msg[offset++] = siglen;
    if (siglen > 0) {
        memcpy(msg + offset, sig, siglen);
        offset += siglen;
    }
    uint16_t net_nb_validations = htons(nb_validations);
    memcpy(msg + offset, &net_nb_validations, sizeof(net_nb_validations));
    offset += sizeof(net_nb_validations);

    // Ajout des signatures des pairs si NB <= 3
    if (nb_validations <= 3 && nb_validations > 0) {
        for (int i = 0; i < nb_validations; i++) {
            uint16_t net_pid = htons(ids[i]);
            memcpy(msg + offset, &net_pid, sizeof(uint16_t));
            offset += sizeof(uint16_t);
            msg[offset++] = siglens[i];
            memcpy(msg + offset, sigs[i], siglens[i]);
            offset += siglens[i];
        }
    }
    return (int)offset;
}

int parse_msg_2(const uint8_t *buf, size_t len, struct message_2 *msg) {
    if (len < 3) return -1;

    size_t offset = 0;
    uint8_t code = buf[offset++];
    if (code != 2) return -2;

    msg->id = ntohs(*(uint16_t *)(buf + offset));
    offset += 2;
    msg->lmess = buf[offset++];
    if (msg->lmess > 255 || offset + msg->lmess + 1 > len)
        return -3;
    memcpy(msg->mess, buf + offset, msg->lmess);
    msg->mess[msg->lmess] = '\0';
    offset += msg->lmess;
    msg->lsig = buf[offset++];
    if (msg->lsig > ED25519_SIGNATURE_SIZE || offset + msg->lsig > len)
        return -4;
    if (msg->lsig > 0)
        memcpy(msg->sig, buf + offset, msg->lsig);
    offset += msg->lsig;
    msg->nb_validations = ntohs(*(uint16_t *)(buf + offset));
    offset += sizeof(uint16_t);

    // Décodage des signatures des pairs si NB <= 3
    if (msg->nb_validations <= 3 && msg->nb_validations > 0) {
        for (int i = 0; i < msg->nb_validations; i++) {
            if (offset + 3 > len) return -5;
            msg->ids[i] = ntohs(*(uint16_t *)(buf + offset));
            offset += sizeof(uint16_t);
            msg->siglens[i] = buf[offset++];
            if (offset + msg->siglens[i] > len) return -6;
            memcpy(msg->sigs[i], buf + offset, msg->siglens[i]);
            offset += msg->siglens[i];
        }
    }
    return 0;
}

// ---------------------------------------------------------CODE 16 ET 17-------------------------------
int msg_16_17(uint8_t *msg, uint8_t code, uint16_t id, uint32_t numv) {
    if (!msg) return -1;
    
    if (code != 16 && code != 17) return -1;
    
    msg[0] = code; 
    
    uint16_t id_net = htons(id);
    memcpy(&msg[1], &id_net, sizeof(id_net));
    
    uint32_t numv_net = htonl(numv);
    memcpy(&msg[3], &numv_net, sizeof(numv_net));
    
    return 7; 
}

int parse_msg_16_17(uint8_t *msg, size_t msg_len, struct message_16_17 *msg_struct) {
    if (!msg || !msg_struct || msg_len < 7) return -1;
    
    msg_struct->code = msg[0];
    if (msg_struct->code != 16 && msg_struct->code != 17) return -1;
    
    uint16_t id_net;
    memcpy(&id_net, &msg[1], sizeof(id_net));
    msg_struct->id = ntohs(id_net);
    
    uint32_t numv_net;
    memcpy(&numv_net, &msg[3], sizeof(numv_net));
    msg_struct->numv = ntohl(numv_net);
    
    return 0;
}

int msg_30(uint8_t *buf, uint32_t numv, char *mess) {
    if (!buf || !mess) return -1;

    buf[0] = 30; 

    uint32_t numv_net = htonl(numv);
    memcpy(&buf[1], &numv_net, sizeof(numv_net)); 

    uint8_t lmess = (uint8_t)strlen(mess); 
    buf[5] = lmess; 
    memcpy(&buf[6], mess, lmess); 

    return 6 + lmess; 
}

int parse_msg_30(uint8_t *msg, size_t len, struct message_30 *out) {
    if (len < 6) return -1; // CODE(1) + NUMV(4) + LMESS(1) = 6 octets mini

    size_t offset = 0;

    uint8_t code = msg[offset++];
    if (code != 30) return -2;
    out->code = code;

    out->numv = ntohl(*(uint32_t *)(msg + offset));
    offset += 4;

    out->lmess = msg[offset++];
    if (out->lmess > 255 || offset + out->lmess > len)
        return -3;

    memcpy(out->mess, msg + offset, out->lmess);
    out->mess[out->lmess] = '\0';

    return 0;
}


// --------------------------- CODE 6 -----------------------------------------------
int msg_6(uint8_t *msg, uint16_t id_peer, struct in6_addr ip, uint16_t port_tcp, unsigned char *cle)
{
    size_t offset = 0;
    msg[offset++] = 6; // CODE = 6

    
    msg[offset++] = (id_peer >> 8) & 0xFF;
    msg[offset++] = id_peer & 0xFF;


    memcpy(msg + offset, &ip, 16);
    offset += 16;

    msg[offset++] = (port_tcp >> 8) & 0xFF;
    msg[offset++] = port_tcp & 0xFF;


    memcpy(msg + offset, cle, 113);
    offset += 113;

    return offset; 
}

int parse_msg_6(uint8_t *msg, size_t msg_len, struct message_6 *msg_struct)
{
    if (msg_len < 1 + 2 + 16 + 2 + 113)
        return -1; 

    size_t offset = 0;

    msg_struct->code = msg[offset++];
    if (msg_struct->code != 6)
        return -1;

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

int message_7_header(uint8_t *buffer, size_t buffer_size, EnchereSocket q) {
    if (!buffer || buffer_size < 22) {
        fprintf(stderr, "Buffer too small for message 7 header (need at least 22 bytes, got %zu)\n", buffer_size);
        return -1;
    }

    size_t offset = 0;

    buffer[offset++] = 7;

    uint16_t id_net = htons(q.id_enchere);
    memcpy(buffer + offset, &id_net, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    memcpy(buffer + offset, &q.group, sizeof(struct in6_addr));
    offset += sizeof(struct in6_addr);

    uint16_t port_net = htons(q.port_enchere);
    memcpy(buffer + offset, &port_net, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    uint16_t nb_net = htons(q.nb_pairs);
    memcpy(buffer + offset, &nb_net, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    char str_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &q.group, str_ip, INET6_ADDRSTRLEN);
    printf("Debug - Message 7 header created:\n");
    printf("  - CODE: %d\n", buffer[0]);
    printf("  - ID_Q: %d\n", q.id_enchere);
    printf("  - Multicast address: %s\n", str_ip);
    printf("  - Port: %d\n", q.port_enchere);
    printf("  - Number of peers: %d\n", q.nb_pairs);
    printf("  - Total message size: %zu bytes\n", offset);

    return offset; 
}

int recevoir_message_7_header(int socket, EnchereSocket *enchere) {
    uint8_t buffer[23]; 
    memset(buffer, 0, sizeof(buffer));

    size_t total_received = 0;

    while (total_received < 23) {
    ssize_t received = recv(socket, buffer + total_received, 23 - total_received, 0);
    // ssize_t received = SSL_read(socket, buffer + total_received, sizeof(buffer) - total_received);
        if (received < 0) {
            perror("Erreur lors de la réception des données TCP");
            return -1;
        } 
    //     // else if (received == 0) {
    //     //     fprintf(stderr, "Connexion fermée par le pair avant réception complète.\n");
    //     //     return -1;
    //     // }
        total_received += received;
    }

    printf("Debug - Total reçu : %zu octets\n", total_received);

    size_t offset = 0;

    uint8_t code = buffer[offset++];
    if (code != 7) {
        fprintf(stderr, "Erreur : code de message invalide (reçu %d, attendu 7).\n", code);
        return -1;
    }

    uint16_t id_q;
    memcpy(&id_q, buffer + offset, sizeof(uint16_t));
    enchere->id_enchere = ntohs(id_q);
    offset += sizeof(uint16_t);

    memcpy(&enchere->group, buffer + offset, sizeof(struct in6_addr));
    offset += sizeof(struct in6_addr);

    uint16_t port;
    memcpy(&port, buffer + offset, sizeof(uint16_t));
    enchere->port_enchere = ntohs(port);
    offset += sizeof(uint16_t);

    uint16_t nb_pairs;
    memcpy(&nb_pairs, buffer + offset, sizeof(uint16_t));
    enchere->nb_pairs = ntohs(nb_pairs);
    offset += sizeof(uint16_t);

    // Debug print
    char str_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &enchere->group, str_ip, sizeof(str_ip));
    printf("Message 7 reçu :\n");
    printf("  - CODE: %d\n", code);
    printf("  - ID_Q: %d\n", enchere->id_enchere);
    printf("  - Multicast address: %s\n", str_ip);
    printf("  - Port: %d\n", enchere->port_enchere);
    printf("  - Number of peers: %d\n", enchere->nb_pairs);

    return 0;
}

void envoyer_infos_peers(int socket, EnchereSocket *enchere) {
    if (!enchere || !enchere->liste_participants) {
        fprintf(stderr, "Erreur : liste des participants vide ou enchère invalide.\n");
        return;
    }

    peer_list *current = enchere->liste_participants;

    do {
        uint8_t msg[133];
        size_t offset = 0;

        uint16_t id_net = htons(current->id);
        memcpy(msg + offset, &id_net, sizeof(uint16_t));
        offset += sizeof(uint16_t);

        memcpy(msg + offset, &current->ip, sizeof(struct in6_addr));
        offset += sizeof(struct in6_addr);

        memcpy(msg + offset, current->cle, 113);
        offset += 113;

        uint16_t port_net = htons(current->port_tcp);
        memcpy(msg + offset, &port_net, sizeof(uint16_t));
        offset += sizeof(uint16_t);

        if (offset != 133) {
            fprintf(stderr, "Erreur : taille du message incorrecte (%zu octets, attendu 133).\n", offset);
            return;
        }

        ssize_t sent = 0;
        while (sent < sizeof(msg)) {
            ssize_t result = send(socket, msg + sent, sizeof(msg) - sent, 0);
            if (result < 0) {
                perror("Erreur lors de l'envoi du message");
                return;
            }
            sent += result;
        }

        printf("peer ID : %d \n", current->id);
        current = current->next;
        sleep(1);
    } while (current != NULL);
    printf("Tous les pairs ont été envoyés avec succès.\n");
}

int recevoir_infos_peer(int socket, EnchereSocket *enchere) {
    if (!enchere) {
        fprintf(stderr, "Erreur : enchère invalide.\n");
        return -1;
    }

    uint8_t buffer[133]; 
    size_t total_received = 0;

    
    while (total_received < sizeof(buffer)) {
        ssize_t received = recv(socket, buffer + total_received, sizeof(buffer) - total_received, 0);
        // ssize_t received = SSL_read(socket, buffer + total_received, sizeof(buffer) - total_received);
        if (received < 0) {
            perror("Erreur lors de la réception des données TCP");
            return -1;
        } 
        else if (received == 0) {
            // fprintf(stderr, "Connexion fermée par le pair avant réception complète.\n");
            // return -1;
            break; // Si la connexion est fermée, on sort de la boucle
        }
        total_received += received;
    }

    printf("Debug - Total reçu : %zu octets\n", total_received);

    if (total_received != sizeof(buffer)) {
        fprintf(stderr, "Erreur : taille du message incorrecte (%zu octets, attendu 133).\n", total_received);
        return -1;
    }

    size_t offset = 0;

    uint16_t id = ntohs(*(uint16_t *)(buffer + offset));
    offset += sizeof(uint16_t);

    struct in6_addr ip;
    memcpy(&ip, buffer + offset, sizeof(struct in6_addr));
    offset += sizeof(struct in6_addr);

    unsigned char cle[113];
    memcpy(cle, buffer + offset, 113);
    offset += 113;

    uint16_t port = ntohs(*(uint16_t *)(buffer + offset));
    offset += sizeof(uint16_t);

    if (offset != 133) {
        fprintf(stderr, "Erreur : taille du message incorrecte (%zu octets, attendu 133).\n", offset);
        return -1;
    }

    // Ajouter le peer à la liste des participants de l'enchère
    // print ip 
    char str_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip, str_ip, INET6_ADDRSTRLEN);
    printf("Debug - IP du peer : %s\n", str_ip);
    if (add_peer(&enchere->liste_participants, id, ip, port, cle) != 0) {
        fprintf(stderr, "Erreur lors de l'ajout du peer à la liste des participants.\n");
        return -1;
    }

    // Incrémenter le nombre de pairs dans l'enchère
    p.encheres[p.enchere_active].nb_pairs += 1;

    printf("Peer ajouté avec succès : ID=%d, Port=%d\n", id, port);
    return 0;
}


// Function to create finalization warning message (code 11)
int msg_11(uint8_t *msg, uint16_t id, uint32_t numv, uint32_t prix) {
    if (!msg) return -1;
    
    msg[0] = 11; 
    
    uint16_t id_net = htons(id);
    memcpy(&msg[1], &id_net, sizeof(id_net));
    
    uint32_t numv_net = htonl(numv);
    memcpy(&msg[3], &numv_net, sizeof(numv_net));
    
    uint32_t prix_net = htonl(prix);
    memcpy(&msg[7], &prix_net, sizeof(prix_net));
    
    return 11;
}

int msg_12(uint8_t *msg, uint16_t id, uint32_t numv, uint32_t prix) {
    if (!msg) return -1;
    
    msg[0] = 12; 

    uint16_t id_net = htons(id);
    memcpy(&msg[1], &id_net, sizeof(id_net));
    
    uint32_t numv_net = htonl(numv);
    memcpy(&msg[3], &numv_net, sizeof(numv_net));
 
    uint32_t prix_net = htonl(prix);
    memcpy(&msg[7], &prix_net, sizeof(prix_net));
    
    return 11; 
}


int parse_msg_11(uint8_t *msg, size_t msg_len, FinalizationWarningMessage *msg_struct) {
    if (!msg || !msg_struct || msg_len < 11) return -1;
    
    msg_struct->code = msg[0];
    if (msg_struct->code != 11) return -1;
 
    uint16_t id_net;
    memcpy(&id_net, &msg[1], sizeof(id_net));
    msg_struct->id = ntohs(id_net);
  
    uint32_t numv_net;
    memcpy(&numv_net, &msg[3], sizeof(numv_net));
    msg_struct->numv = ntohl(numv_net);

    uint32_t prix_net;
    memcpy(&prix_net, &msg[7], sizeof(prix_net));
    msg_struct->prix = ntohl(prix_net);
    
    return 0;
}

int parse_msg_12(uint8_t *msg, size_t msg_len, FinalizationMessage *msg_struct) {
    if (!msg || !msg_struct || msg_len < 11) return -1;
    
    msg_struct->code = msg[0];
    if (msg_struct->code != 12) return -1;
    
    uint16_t id_net;
    memcpy(&id_net, &msg[1], sizeof(id_net));
    msg_struct->id = ntohs(id_net);

    uint32_t numv_net;
    memcpy(&numv_net, &msg[3], sizeof(numv_net));
    msg_struct->numv = ntohl(numv_net);
    
    uint32_t prix_net;
    memcpy(&prix_net, &msg[7], sizeof(prix_net));
    msg_struct->prix = ntohl(prix_net);
    
    return 0;
}

int msg_18(uint8_t *msg, uint16_t id, uint16_t nb, uint16_t *ids) {
    if (!msg || !ids) return -1;
    
    msg[0] = 18;

    uint16_t id_net = htons(id);
    memcpy(msg + 1, &id_net, sizeof(uint16_t));

    uint16_t nb_net = htons(nb);
    memcpy(msg + 3, &nb_net, sizeof(uint16_t));

    for (int i = 0; i < nb; i++) {
        uint16_t id_net = htons(ids[i]);
        memcpy(msg + 5 + (i * sizeof(uint16_t)), &id_net, sizeof(uint16_t));
    }
    
    return 5 + (nb * sizeof(uint16_t)); 
}

int parse_msg_18(uint8_t *msg, size_t msg_len, struct message_18 *msg_struct) {
    if (!msg || !msg_struct || msg_len < 5) return -1;

    if (msg[0] != 18) return -1;

    memcpy(&msg_struct->id, msg + 1, sizeof(uint16_t));
    msg_struct->id = ntohs(msg_struct->id);

    memcpy(&msg_struct->nb, msg + 3, sizeof(uint16_t));
    msg_struct->nb = ntohs(msg_struct->nb);

    size_t expected_len = 5 + (msg_struct->nb * sizeof(uint16_t));
    if (msg_len < expected_len) return -1;

    struct message_18 *new_struct = malloc(sizeof(struct message_18) + msg_struct->nb * sizeof(uint16_t));
    if (!new_struct) return -1;

    new_struct->code = msg_struct->code;
    new_struct->id = msg_struct->id;
    new_struct->nb = msg_struct->nb;

    for (int i = 0; i < msg_struct->nb; i++) {
        memcpy(&new_struct->ids[i], msg + 5 + (i * sizeof(uint16_t)), sizeof(uint16_t));
        new_struct->ids[i] = ntohs(new_struct->ids[i]);
    }

    memcpy(msg_struct, new_struct, sizeof(struct message_18) + msg_struct->nb * sizeof(uint16_t));
    free(new_struct);
    
    return 0;
}

int msg_20(uint8_t *msg, uint16_t id, uint16_t nb, uint16_t *peer_ids, uint8_t *sig_lengths, uint8_t **signatures) {
    int offset = 0;
 
    msg[offset++] = 20;
    
    uint16_t id_net = htons(id);
    memcpy(msg + offset, &id_net, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    uint16_t nb_net = htons(nb);
    memcpy(msg + offset, &nb_net, sizeof(uint16_t));
    offset += sizeof(uint16_t);
    
    // Concatenate peer IDs, signature lengths and signatures
    for (int i = 0; i < nb; i++) {

        uint16_t peer_id_net = htons(peer_ids[i]);
        memcpy(msg + offset, &peer_id_net, sizeof(uint16_t));
        offset += sizeof(uint16_t);
        
        msg[offset++] = sig_lengths[i];

        memcpy(msg + offset, signatures[i], sig_lengths[i]);
        offset += sig_lengths[i];
    }
    
    return offset;
}
