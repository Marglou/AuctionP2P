// message.c

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h> // Pour htonl et htons
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <unistd.h> // pour close()
#include <netinet/in.h> // Pour les fonctions de conversion de réseau

#include "../include/message.h"
#include "../include/peer.h"
#include "../include/superviseur.h"
#include "../include/enchere.h"
#include "../include/connexion.h"





// --------------------------- CODE 4 -----------------------------------------------
int msg_4(uint8_t *msg, uint16_t id_peer, uint16_t port_tcp)
{
    // 1 octect pour le code
    // 2 octets pour l'ID du pair
    // 16 octets pour l'adresse perso
    // 2 octets pour le port TCP
    uint8_t code = 4;
    struct in6_addr adresse_perso;

    // Récupérer l'adresse perso
    if (get_adresse_perso_par_index(&adresse_perso, global_iface_index) != 0)
    {
        fprintf(stderr, "Erreur pour récupérer l'adresse perso\n");
        return -1;
    }

    // Construction du message
    msg[0] = code;

    uint16_t id_net = htons(id_peer);    // Convertir en format réseau
    uint16_t port_net = htons(port_tcp); // Convertir en format réseau

    memcpy(&msg[1], &id_net, 2);         // ID du pair
    memcpy(&msg[3], &adresse_perso, 16); // Adresse IP
    memcpy(&msg[19], &port_net, 2);      // Port

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

int msg_5(uint8_t *msg, uint16_t id_peer, uint16_t port_tcp, unsigned char *public_key)
{
    struct in6_addr ip;
    size_t offset = 0;
    msg[offset++] = 5; // CODE = 5

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

    return offset; // taille totale écrite
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
    msg[0] = 50; // CODE = 50
    return 1;    // taille totale écrite
}

int parse_msg_50(uint8_t *msg, size_t msg_len, struct message_50 *msg_struct)
{
    if (msg_len < 1)
        return -1; // message trop court

    msg_struct->code = msg[0];
    if (msg_struct->code != 50)
        return -1;
    return 0;
}

// --------------------------- CODE 51 -----------------------------------------------
int msg_51(uint8_t *msg, uint16_t id)
{
    msg[0] = 51; // CODE = 51
    msg[1] = (id >> 8) & 0xFF;
    msg[2] = id & 0xFF;
    return 3; // taille totale écrite
}

int parse_msg_51(uint8_t *msg, size_t msg_len, struct message_51 *msg_struct)
{
    if (msg_len < 3)
        return -1; // message trop court

    msg_struct->code = msg[0];
    if (msg_struct->code != 51)
        return -1;

    msg_struct->id = (msg[1] << 8) | msg[2];
    return 0;
}

int msg_8(uint8_t *msg, uint16_t id, uint32_t numv, uint32_t prix)
{
    msg[0] = 8; // Code du message

    // ID (2 octets, réseau)
    uint16_t net_id = htons(id);
    memcpy(&msg[1], &net_id, sizeof(net_id));

    // numv (4 octets, réseau)
    uint32_t net_numv = htonl(numv);
    memcpy(&msg[3], &net_numv, sizeof(net_numv));

    // prix (4 octets, réseau)
    uint32_t net_prix = htonl(prix);
    memcpy(&msg[7], &net_prix, sizeof(net_prix));

    return 11; // Taille totale du message
}

void envoyer_message(int socket, uint16_t id)
{
    QuitMessage msg;
    msg.CODE = 13;      // Code du message de fin
    msg.ID = htons(id); // Conversion en big-endian

    send(socket, &msg, sizeof(msg), 0);
}

// Fonction pour envoyer le message
void envoyer_rejet(int socket, uint8_t code, uint16_t id, uint32_t numv, uint32_t prix)
{
    RejetMessage msg;
    msg.CODE = code; // 14 ou 15
    // quand on fait apelle a la fonction on met 14 ou 15, CODE vaut 14 si l'enchère est rejetée car en concurrence avec une autre enchère et 15 sinon
    msg.ID = htons(id);     // Conversion en big-endian
    msg.NUMV = htonl(numv); // Conversion en big-endian
    msg.PRIX = htonl(prix); // Conversion en big-endian

    send(socket, &msg, sizeof(msg), 0);
}

void envoyer_vente(int socket, bool etape, uint16_t id, uint32_t numv, uint32_t prix)
{
    FinalisationVenteMessage msg;
    if (etape == true)
    {                 // true pour initier false pour enrichier
        msg.CODE = 8; // supeviseur
    }
    else
    {
        msg.CODE = 9; //
    }
    // la gestion de l'id dans l'appel
    // faire verif si on est true le code doit etre 8 et c'est oblige superviseur
    // pour la cloture soit superviseur si personne la prend ou gagnant si reuss
    msg.ID = htons(id);
    msg.NUMV = htonl(numv);
    msg.PRIX = htonl(prix);

    send(socket, &msg, sizeof(msg), 0);
}

void envoyer_finalisation_vente(int socket, bool etape, uint16_t id, uint32_t numv, uint32_t prix)
{
    FinalisationVenteMessage msg;
    if (etape == true)
    { // true pour cloture false pour finalisation
        msg.CODE = 11;
    }
    else
    {
        msg.CODE = 12;
    }
    // la gestion de l'id dans l'appel
    // faire verif si on est true le code doit etre 11 et c'est oblige superviseur
    // pour la cloture soit superviseur si personne la prend ou gagnant si reuss
    msg.ID = htons(id);
    msg.NUMV = htonl(numv);
    msg.PRIX = htonl(prix);

    send(socket, &msg, sizeof(msg), 0);
}

void envoyer_disparition(int socket, bool superviseur, uint16_t id, uint32_t numv, uint16_t *ids_disparus, uint16_t nb)
{
    if (superviseur)
    {
        // Cas d'un superviseur disparu (CODE = 16 ou 17)
        DisparitionSuperviseurMessage msg;
        msg.CODE = 16; // Par défaut, CODE = 16 (annulation d'une vente)
        msg.ID = htons(id);
        msg.NUMV = htonl(numv);

        send(socket, &msg, sizeof(msg), 0);
    }
    else
    {
        // Cas de disparition de pairs non superviseurs (CODE = 18)
        size_t taille_msg = sizeof(DisparitionPairsMessage) + nb * sizeof(uint16_t);
        DisparitionPairsMessage *msg = malloc(taille_msg);
        if (!msg)
        {
            perror("Erreur d'allocation mémoire");
            return;
        }

        msg->CODE = 18;
        msg->ID = htons(id);
        msg->NB = htons(nb);

        // Ajouter les identifiants des pairs disparus
        for (int i = 0; i < nb; i++)
        {
            msg->ids[i] = htons(ids_disparus[i]);
        }

        // Envoi du message
        send(socket, msg, taille_msg, 0);
        free(msg);
    }
}

void envoyer_enchere(int socket, uint16_t id, uint32_t numv, uint32_t prix)
{
    VenteMessage msg;
    msg.CODE = 10; // Code d'enchère
    msg.ID = htons(id);
    msg.NUMV = htonl(numv);
    msg.PRIX = htonl(prix);
    send(socket, &msg, sizeof(msg), 0);
}

// Format ED25519 public key with header and trailer texts
int format_ed25519_public_key(unsigned char *cle, EVP_PKEY *pubkey)
{
    // Header text: "-----BEGIN PUBLIC KEY-----\n"
    const char *header = "-----BEGIN PUBLIC KEY-----\n";
    memcpy(cle, header, strlen(header));
    size_t offset = strlen(header);

    // Get raw public key bytes
    unsigned char raw_key[32];
    size_t raw_len = sizeof(raw_key);
    if (EVP_PKEY_get_raw_public_key(pubkey, raw_key, &raw_len) != 1)
    {
        fprintf(stderr, "Error getting raw public key\n");
        return -1;
    }

    // Base64 encode the raw key
    char base64_key[45];
    int base64_len = EVP_EncodeBlock((unsigned char *)base64_key, raw_key, raw_len);
    if (base64_len < 0)
    {
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
    if (offset != 113)
    {
        fprintf(stderr, "Error: formatted key length is %zu, expected 113\n", offset);
        return -1;
    }

    return 0;
}

// --------------------------- CODE 6 -----------------------------------------------
int msg_6(uint8_t *msg, uint16_t id_peer, struct in6_addr ip, uint16_t port_tcp, unsigned char *cle)
{
    size_t offset = 0;
    msg[offset++] = 6; // CODE = 6

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

    return offset; // taille totale écrite
}

int parse_msg_6(uint8_t *msg, size_t msg_len, struct message_6 *msg_struct)
{
    if (msg_len < 1 + 2 + 16 + 2 + 113)
        return -1; // message trop court

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

int msg_7(uint8_t *buffer, size_t buffer_size, EnchereSocket q, uint16_t nb_pairs) {
    if (!buffer || buffer_size < 22) {
        fprintf(stderr, "Buffer too small for message 7 (need at least 22 bytes, got %zu)\n", buffer_size);
        return -1;
    }

    size_t offset = 0;

    // CODE = 7
    buffer[offset++] = 7;

    // Debug print the multicast address before sending
    char str_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &q.group, str_ip, INET6_ADDRSTRLEN);
    printf("Debug - Preparing message 7 with multicast address: %s\n", str_ip);

    // Verify this is a valid multicast address before sending
    if (!IN6_IS_ADDR_MULTICAST(&q.group)) {
        fprintf(stderr, "Invalid multicast address in msg_7: %s\n", str_ip);
        return -1;
    }

    // ID_Q (2 octets)
    uint16_t id_net = htons(q.id_enchere);
    memcpy(buffer + offset, &id_net, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    // IP_enchere (16 octets) - Copy the multicast address
    memcpy(buffer + offset, &q.group, sizeof(struct in6_addr));
    offset += sizeof(struct in6_addr);

    // PORT (2 octets)
    uint16_t port_net = htons(q.port_enchere);
    memcpy(buffer + offset, &port_net, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    // NB (2 octets)
    uint16_t nb_net = htons(nb_pairs);
    memcpy(buffer + offset, &nb_net, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    // Debug print final message details
    printf("Debug - Message 7 details:\n");
    printf("  - ID_Q: %d\n", q.id_enchere);
    printf("  - Multicast address: %s\n", str_ip);
    printf("  - Port: %d\n", q.port_enchere);
    printf("  - Number of peers: %d\n", nb_pairs);
    printf("  - Total message size: %zu bytes\n", offset);

    return offset; // Return the actual size of the message
}

int decode_message_7(uint8_t *buffer, size_t buffer_size) {
    if (!buffer || buffer_size < 22) {
        fprintf(stderr, "Buffer too small for message 7 (need at least 22 bytes, got %zu)\n", buffer_size);
        return -1;
    }

    size_t offset = 0;

    // CODE = 7 (vérification de l'entête)
    uint8_t code = buffer[offset++];
    if (code != 7) {
        fprintf(stderr, "Invalid message code: %d (expected 7)\n", code);
        return -1;
    }

    // ID_Q
    uint16_t id_q;
    memcpy(&id_q, buffer + offset, sizeof(uint16_t));
    id_q = ntohs(id_q);
    offset += sizeof(uint16_t);

    // IP_enchere - Copy the multicast address
    struct in6_addr multicast_addr;
    memcpy(&multicast_addr, buffer + offset, sizeof(struct in6_addr));
    offset += sizeof(struct in6_addr);

    // Debug print before validation
    char str_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &multicast_addr, str_ip, INET6_ADDRSTRLEN);
    printf("Debug - Raw multicast address from message: %s\n", str_ip);

    // Verify this is a valid multicast address
    if (!IN6_IS_ADDR_MULTICAST(&multicast_addr)) {
        fprintf(stderr, "Invalid multicast address in message 7: %s\n", str_ip);
        return -1;
    }

    // PORT
    uint16_t port;
    memcpy(&port, buffer + offset, sizeof(uint16_t));
    port = ntohs(port);
    offset += sizeof(uint16_t);

    // NB (nombre de pairs)
    uint16_t nb_pairs;
    memcpy(&nb_pairs, buffer + offset, sizeof(uint16_t));
    nb_pairs = ntohs(nb_pairs);
    offset += sizeof(uint16_t);

    // Store the values in the encheres array
    encheres[enchere_active].id_enchere = id_q;
    memcpy(&encheres[enchere_active].group, &multicast_addr, sizeof(struct in6_addr));
    encheres[enchere_active].port_enchere = port;
    encheres[enchere_active].nb_pairs = nb_pairs;

    // Debug print after validation
    inet_ntop(AF_INET6, &encheres[enchere_active].group, str_ip, INET6_ADDRSTRLEN);
    printf("Debug - Message 7 decoded successfully:\n");
    printf("  - ID_Q: %d\n", encheres[enchere_active].id_enchere);
    printf("  - Multicast address: %s\n", str_ip);
    printf("  - Port: %d\n", encheres[enchere_active].port_enchere);
    printf("  - Number of peers: %d\n", encheres[enchere_active].nb_pairs);

    return 0;
}


int parse_msg_7(uint8_t *buffer, size_t buffer_size, struct message_7 *participants) {
    if (!buffer || !participants || buffer_size < 22) return -1;
    size_t offset = 0;

    // CODE
    if (buffer[offset++] != 7) return -1;

    // ID_Q
    memcpy(&participants->id_q, buffer + offset, sizeof(uint16_t));
    participants->id_q = ntohs(participants->id_q);
    offset += sizeof(uint16_t);

    // IP_enchere
    memcpy(&participants->ip_enchere, buffer + offset, 16);
    offset += 16;

    // PORT
    memcpy(&participants->port_enchere, buffer + offset, sizeof(uint16_t));
    participants->port_enchere = ntohs(participants->port_enchere);
    offset += sizeof(uint16_t);

    // NB
    memcpy(&participants->nb, buffer + offset, sizeof(uint16_t));
    participants->nb = ntohs(participants->nb);
    offset += sizeof(uint16_t);

    // Liste des peers
    participants->liste_peers = NULL;
    msg7_peer **last_ptr = &participants->liste_peers;

    for (int i = 0; i < participants->nb; ++i) {
        if (offset + 2 + 16 + 2 + 113 > buffer_size) return -1;

        msg7_peer *p = malloc(sizeof(msg7_peer));
        if (!p) return -1;

        // ID
        memcpy(&p->id, buffer + offset, sizeof(uint16_t));
        p->id = ntohs(p->id);
        offset += sizeof(uint16_t);

        // IP
        memcpy(&p->ip, buffer + offset, 16);
        offset += 16;

        // PORT
        memcpy(&p->port, buffer + offset, sizeof(uint16_t));
        p->port = ntohs(p->port);
        offset += sizeof(uint16_t);

        // CLE
        memcpy(p->cle, buffer + offset, 113);
        offset += 113;

        p->next = NULL;
        *last_ptr = p;
        last_ptr = &p->next;
    }

    return 0;
}

void free_msg7 (struct message_7 *info) {
    if (!info) return;

    msg7_peer *p = info->liste_peers;
    while (p) {
        msg7_peer *next = p->next;
        free(p);
        p = next;
    }

    info->liste_peers = NULL;
}


// Fonction pour libérer une liste de 'peer'
void free_peer_list(struct peer *list) {
    struct peer *current = list;
    struct peer *next;

    while (current != NULL) {
        next = current->next;  // Sauvegarder l'élément suivant
        free(current);  // Libérer l'élément actuel
        current = next;  // Passer à l'élément suivant
    }
}

#define HEADER_SIZE 22
#define PEER_ENTRY_SIZE 133

int recv_full(int sock, uint8_t *buffer, size_t size) {
    size_t total_received = 0;
    while (total_received < size) {
        ssize_t len = recv(sock, buffer + total_received, size - total_received, 0);
        if (len <= 0) {
            perror("recv");
            return -1;
        }
        total_received += len;
    }
    return 0;
}

int receive_msg7(int socket_P, struct message_7 *msg7) {
    uint8_t header[HEADER_SIZE];

    // Étape 1 : lire l'en-tête
    if (recv_full(socket_P, header, HEADER_SIZE) != 0)
        return -1;

    // Lire NB (nombre de pairs)
    uint16_t nb;
    memcpy(&nb, header + 20, sizeof(uint16_t));
    nb = ntohs(nb);

    // Taille totale
    size_t total_size = HEADER_SIZE + nb * PEER_ENTRY_SIZE;
    uint8_t *full_msg = malloc(total_size);
    if (!full_msg) {
        perror("malloc");
        return -1;
    }

    // Copier l'en-tête déjà lu
    memcpy(full_msg, header, HEADER_SIZE);

    // Étape 2 : lire le reste
    if (recv_full(socket_P, full_msg + HEADER_SIZE, total_size - HEADER_SIZE) != 0) {
        free(full_msg);
        return -1;
    }

    // Étape 3 : parse
    if (parse_msg_7(full_msg, total_size, msg7) != 0) {
        fprintf(stderr, "Erreur de parsing du message 7.\n");
        free(full_msg);
        return -1;
    }

    free(full_msg);
    return 0;
}


// void envoyer_info_auction(int socket, uint16_t id, uint32_t numv, uint32_t prix,
//                           const unsigned char *message, size_t message_len,
//                           const unsigned char *signature)
// {
//     uint8_t msg[1 + 2 + 4 + 4 + 1 + 256 + 1 + ED25519_SIGNATURE_SIZE]; // Maximum size
//     int msg_len = msg_7(msg, id, numv, prix, message, message_len, signature, ED25519_SIGNATURE_SIZE);
//     if (msg_len > 0)
//     {
//         send(socket, msg, msg_len, 0);
//     }
// }
