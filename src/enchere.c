//enchere.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <asm-generic/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <net/if.h>


#include "../include/enchere.h"
#include "../include/superviseur.h"
#include "../include/peer.h"
#include "../include/message.h"


void join_enchere(const char *id, const char *group){
    //  Vérifier si peut rejoindre l'enchère
    if (nb_encheres >= MAX_ENCHERES) {
        fprintf(stderr, "Nombre maximum d'enchères atteint.\n");
        return;
    }

    // Vérifier si l'enchère existe déjà
    for (int i = 0; i < nb_encheres; i++) {
        if (strcmp(encheres[i].id, id) == 0) {
            fprintf(stderr, "Vous êtes déjà dans l'enchère %s.\n", id);
            return;
        }
    }

    // Création du socket dédié à l'enchère
    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket enchere");
        return;
    }

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));

    struct sockaddr_in6 addr = {0};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(PORT_ENCHERE);
    addr.sin6_addr = in6addr_any;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind enchere");
        close(sock);
        return;
    }

    // S'abonner au groupe multicast spécifique à l'enchère
    struct ipv6_mreq mreq;
    if (inet_pton(AF_INET6, group, &mreq.ipv6mr_multiaddr) != 1) {
        perror("inet_pton (group enchere)");
        close(sock);
        return;
    }
    mreq.ipv6mr_interface = global_iface_index;

    if (setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) < 0) {
        perror("setsockopt (join group enchere)");
        close(sock);
        return;
    }

    // Sauvegarde dans la liste des enchères
    strncpy(encheres[nb_encheres].id, id, sizeof(encheres[nb_encheres].id));
    strncpy(encheres[nb_encheres].group, group, sizeof(encheres[nb_encheres].group));
    encheres[nb_encheres].sock = sock;

    // On passe l'enchère active à celle qui vient d'être rejointe
    enchere_active = nb_encheres;

    int *sock_ptr = malloc(sizeof(int));
    if (!sock_ptr) {
        perror("malloc");
        close(sock);
        return;
    }
    *sock_ptr = sock;

    pthread_t tid;
    pthread_create(&tid, NULL, auction_receiver, sock_ptr);

    printf("Vous avez rejoint l'enchère %s sur %s\n", id, group);

    // Send ACCEPTED message
    char accept_msg[BUF_SIZE];
    snprintf(accept_msg, sizeof(accept_msg), "[ACCEPTED] Vous avez rejoint l'enchère %s\n", id);
    sendto(sock, accept_msg, strlen(accept_msg), 0, (struct sockaddr *)&addr, sizeof(addr));

    nb_encheres++;
}

void creer_enchere()
{
    if (nb_encheres >= MAX_ENCHERES) {
        fprintf(stderr, "Le nombre maximum d'enchères a été atteint.\n");
        return;
    }

    char auction_group[INET6_ADDRSTRLEN];
    char auction_id[64];

    // Génération d'un ID et d'une adresse multicast unique
    snprintf(auction_id, sizeof(auction_id), "%.60s-%d", id_peer, cpt + 1);

    int r = rand() & 0xFFFF; // max 4 chiffres hexadécimaux
    snprintf(auction_group, sizeof(auction_group), "ff15::%x", r);
    
    // // Envoi du message NEW_AUCTION à tous les pairs
    // struct sockaddr_in6 dest = {0};
    // dest.sin6_family = AF_INET6;
    // dest.sin6_port = htons(PORT);
    // if (inet_pton(AF_INET6, GROUP, &dest.sin6_addr) != 1) {
    //     perror("inet_pton (liaison group)");
    //     exit(EXIT_FAILURE);
    // }
    // dest.sin6_scope_id = global_iface_index;

    // char msg[BUF_SIZE];
    // snprintf(msg, sizeof(msg), "[NEW_AUCTION] ID=%s GROUPE=%s\n", auction_id, auction_group);

    // // On utilise le socket global pour l’annonce
    // if (sendto(global_sock, msg, strlen(msg), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
    //     perror("sendto");
    // }

    // Pour l'instant on considère que la personne qui lance l'enchère la rejoint en même temps
    join_enchere(auction_id, auction_group);

    // printf("Vous avez lancé et rejoint une nouvelle enchère : %s (%s)\n", auction_id, auction_group);
    cpt++ ; // Incrémente le compteur d'enchères initiées
}


int handle_incoming_connections(char *ip_dest, uint16_t *port_dest) {
    struct sockaddr_in6 client_addr;
    socklen_t addr_len = sizeof(client_addr);


    int client_sock = accept(socket_tcp, (struct sockaddr *)&client_addr, &addr_len);
    if (client_sock < 0) {
        perror("accept TCP");
        return -1;
    }

    // Convertir l'adresse IP en chaîne lisible
    inet_ntop(AF_INET6, &client_addr.sin6_addr, ip_dest, INET6_ADDRSTRLEN);
    *port_dest = ntohs(client_addr.sin6_port);

    // Réception du message
    char buffer[BUF_SIZE];
    ssize_t len = recv(client_sock, buffer, BUF_SIZE - 1, 0);
    if (len > 0) {
        buffer[len] = '\0';
        printf("Message reçu : %s\n", buffer);
    }

    close(client_sock);
    return 0;
}


int msg_join_enchere() {
    int timeout_sec = 3;
    int max_attempts = 3;
    int attempts = 0;
    char msg[1] = {3}; // CODE 3 pour rejoindre un système d'enchère

    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(PORT);
    inet_pton(AF_INET6, GROUP, &dest.sin6_addr);
    dest.sin6_scope_id = global_iface_index;

    while (attempts < max_attempts) {
        printf("En attente de réponse sur le socket TCP (tentative %d)...\n", attempts + 1);

        uint8_t msg[1 + 2];  // code (1) + port TCP (2)
        msg[0] = 3;

        uint16_t port_tcp_tmp = htons(port_tcp);  // Ton port TCP d'écoute
        memcpy(&msg[1], &port_tcp_tmp, 2);

        // Multidiffusion UDP vers les autres pairs
        sendto(global_sock, msg, sizeof(msg), 0, (struct sockaddr *)&dest, sizeof(dest));

        // Préparation pour select()
        fd_set readfds;
        struct timeval timeout;
        FD_ZERO(&readfds);
        FD_SET(socket_tcp, &readfds);
        timeout.tv_sec = timeout_sec;
        timeout.tv_usec = 0;

        int ret = select(socket_tcp + 1, &readfds, NULL, NULL, &timeout);
        if (ret > 0) {
            // Connexion entrante détectée
            // char ip_dest[INET6_ADDRSTRLEN];
            // uint16_t port_dest;
            // if (handle_incoming_connections(ip_dest, &port_dest) == 0) {
            //     return 0;
            // }

            // Répondre à la demande de connexion
            struct sockaddr_in6 client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int client_sock = accept(socket_tcp, (struct sockaddr *)&client_addr, &addr_len);
            if (client_sock < 0) {
                perror("accept TCP");
                return -1;
            }

            // si le message reçu est de type 4
            char buffer[BUF_SIZE];
            ssize_t len = recv(client_sock, buffer, BUF_SIZE - 1, 0);
            if (len > 0) {
                buffer[len] = '\0';
                uint8_t code = (uint8_t)buffer[0];
                if (code == 4) { // CODE 4 : réponse si enchère active
                    printf("Réponse reçue\n");
                    
                    struct message parsed_msg;  // Structure pour contenir le message parsé
                
                    // Appel de la fonction de parsing
                    if (parse_message((uint8_t *)buffer, len, &parsed_msg) == 0) {
                        // Si le message a été parsé avec succès, on peut traiter les informations
                        printf("Message traité : ID=%u, IP=%s, PORT=%u\n", parsed_msg.id,
                               inet_ntop(AF_INET6, &parsed_msg.ip, buffer, sizeof(buffer)),  // Conversion de l'adresse IP en chaîne de caractères
                               ntohs(parsed_msg.port));  // Conversion du port en format hôte
                    } else {
                        // Si une erreur survient lors du parsing, on affiche un message d'erreur
                        fprintf(stderr, "Erreur lors du traitement du message.\n");
                    }
                
                    // Fermer la connexion après traitement
                    close(client_sock);
                    return 0;
                
                } else {
                    printf("Message reçu avec un code différent de 4 : %s\n", buffer);
                }
                close(client_sock);
            } else {
                perror("recv");
                return -1;
            }

        } else if (ret == 0) {
            printf("Pas de réponse reçue, tentative %d.\n", attempts + 1);
        } else {
            perror("select");
            return -1;
        }

        attempts++;
    }

    printf("Aucune réponse reçue après %d tentatives. Création d'un nouveau système d'enchères.\n", max_attempts);
    creer_enchere();
    return -1;
}



void repondre_demande_liaison(int socket_udp, struct sockaddr_in6 *peer_addr, uint16_t id_local, int socket_tcp, struct in6_addr ip_perso) {
    unsigned char msg[1 + 2 + 16 + 2];  // CODE + ID + IP + PORT
    size_t offset = 0;

    // CODE = 4
    msg[offset++] = 4;

    // ID (2 octets en big-endian)
    msg[offset++] = id_local >> 8;
    msg[offset++] = id_local & 0xFF;

    // IP (16 octets)
    memcpy(msg + offset, &ip_perso, 16);
    offset += 16;
    
    // PORT (2 octets en big-endian)
    struct sockaddr_in6 addr_local;
    socklen_t addrlen = sizeof(addr_local);
    if (getsockname(socket_tcp, (struct sockaddr *)&addr_local, &addrlen) != 0) {
        perror("getsockname");
        return;
    }
    uint16_t port_tcp = ntohs(addr_local.sin6_port); 
    msg[offset++] = port_tcp >> 8;
    msg[offset++] = port_tcp & 0xFF;

    // Création d'une nouvelle socket TCP pour répondre
    int tcp_sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (tcp_sock < 0) {
        perror("Erreur de création du socket TCP");
        return;
    }

    // Connexion à l'adresse du pair avec les informations de peer_addr
    if (connect(tcp_sock, (struct sockaddr *)peer_addr, sizeof(*peer_addr)) < 0) {
        perror("Erreur de connexion TCP");
        close(tcp_sock);
        return;
    }

    // Envoi du message via la connexion TCP
    ssize_t bytes_sent = send(tcp_sock, msg, offset, 0);
    if (bytes_sent < 0) {
        perror("Erreur d'envoi TCP");
    } else {
        printf("Réponse envoyée à un pair en TCP : CODE=4, ID=%u, PORT=%u\n", id_local, port_tcp);
    }

    // Fermeture du socket TCP après l'envoi
    close(tcp_sock);
}

// Thread pour recevoir les messages du groupe d'enchères
void *auction_receiver(void *arg){
    int sock = *(int *)arg;
    free(arg); // Libère la mémoire allouée dynamiquement

    char buffer[BUF_SIZE];
    struct sockaddr_in6 src;
    socklen_t srclen = sizeof(src);

    while (1){
        ssize_t len = recvfrom(sock, buffer, BUF_SIZE - 1, 0,
                               (struct sockaddr *)&src, &srclen);

        if (len > 0){
            buffer[len] = '\0';
            printf("[Enchère] %s", buffer);
            fflush(stdout);
        }
    }
    return NULL;
}


// -------------------- Test pour la diffusion des adresses Persos --------------------
// Envoie l'adresse perso à un pair P en TCP unicast
void envoyer_adressePerso_TCP(const char *ip_dest, int port_dest, const char *adressePerso) {
    int sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket TCP");
        return;
    }

    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    inet_pton(AF_INET6, ip_dest, &dest.sin6_addr);
    dest.sin6_port = htons(port_dest);

    if (connect(sock, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("connect TCP");
        close(sock);
        return;
    }

    send(sock, adressePerso, strlen(adressePerso), 0);
    close(sock);
}


// Écoute sur le port TCP donné et reçoit les adressesPerso pendant un timeout
void recevoir_adressesPerso_TCP(int port_tcp, int timeout_sec) {
    int sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket TCP");
        return;
    }

    struct sockaddr_in6 addr = {0};
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(port_tcp);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind TCP");
        close(sock);
        return;
    }

    listen(sock, 5);

    fd_set fds;
    struct timeval timeout = {.tv_sec = timeout_sec, .tv_usec = 0};

    printf("En attente de réponses TCP pendant %ds...\n", timeout_sec);

    while (1) {
        FD_ZERO(&fds);
        FD_SET(sock, &fds);

        int ready = select(sock + 1, &fds, NULL, NULL, &timeout);
        if (ready < 0) {
            perror("select");
            break;
        } else if (ready == 0) {
            printf("⏱️ Timeout atteint, fin d'écoute TCP.\n");
            break;
        } else {
            int client_sock = accept(sock, NULL, NULL);
            if (client_sock >= 0) {
                char buffer[256];
                int len = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
                if (len > 0) {
                    buffer[len] = '\0';
                    printf("📨 Reçu adressePerso : %s\n", buffer);
                }
                close(client_sock);
            }
        }
    }

    close(sock);
}
