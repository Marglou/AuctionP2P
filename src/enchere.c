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
    int attempts = 0;
    const int timeout_sec = 3;
    const int max_attempts = 3;

    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(PORT);
    inet_pton(AF_INET6, GROUP, &dest.sin6_addr);
    dest.sin6_scope_id = global_iface_index;

    while (attempts++ < max_attempts) {
        printf("Tentative %d : envoi du message CODE 3.\n", attempts);

        // Envoi du message CODE 3 + port TCP
        uint8_t msg[3] = {3};
        uint16_t port_tcp_net = htons(port_tcp);
        memcpy(&msg[1], &port_tcp_net, 2);
        sendto(global_sock, msg, sizeof(msg), 0, (struct sockaddr *)&dest, sizeof(dest));

        // Attente d'une connexion TCP entrante
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(socket_tcp, &readfds);
        struct timeval timeout = { .tv_sec = timeout_sec, .tv_usec = 0 };

        if (select(socket_tcp + 1, &readfds, NULL, NULL, &timeout) > 0) {
            struct sockaddr_in6 client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int client_sock = accept(socket_tcp, (struct sockaddr *)&client_addr, &addr_len);
            if (client_sock < 0) { perror("accept"); continue; }

            uint8_t buffer[BUF_SIZE];
            ssize_t len = recv(client_sock, buffer, BUF_SIZE, 0);
            if (len > 0 && buffer[0] == 4 && num_peers < MAX_PEERS) {
                struct message_4 parsed_msg;
                if (parse_msg_4(buffer, len, &parsed_msg) == 0) {
                    printf("Pair trouvé : ID=%u, port=%u\n", parsed_msg.id, ntohs(parsed_msg.port));
                    discovered_peers[num_peers].id = parsed_msg.id;
                    discovered_peers[num_peers].ip = parsed_msg.ip;
                    discovered_peers[num_peers].port_tcp = parsed_msg.port;
                    num_peers++;
                    close(client_sock);
                    continue;  // On continue à accepter d'autres connexions
                }
            }
            close(client_sock);
        } else {
            printf("Aucune réponse à la tentative %d.\n", attempts);
        }
    }

    if (num_peers > 0) {
        struct peer_info *peer_Q = &discovered_peers[num_peers - 1];  // Dernier pair trouvé
    
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &peer_Q->ip, ip_str, sizeof(ip_str));
    
        uint16_t port = ntohs(peer_Q->port_tcp);  // Port au format hôte
    
        printf("Connexion à : ID=%u, IP=%s, PORT=%u\n", peer_Q->id, ip_str, port);
    
        // int c = connexion_TLS(peer_Q->ip, peer_Q->port_tcp); 
        return 0;  // ou retourne le résultat de la fonction de connexion
    }
    

    printf("Aucune enchère trouvée. Création d'une nouvelle.\n");
    creer_enchere();
    return -1;
}


int connexion_TLS(struct in6_addr ip, uint16_t port) {
    // Implémentation de la connexion TLS ici
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return -1;  // Erreur de création du contexte
    }

    SSL *ssl = SSL_new(ctx);
    if (!ctx) return 1;

    // Créer un socket TCP
    int socket_tcp_client = socket(AF_INET6, SOCK_STREAM, 0);
    if (socket_tcp_client < 0) {
        perror("socket TCP");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return -1;  // Erreur de création du socket
    }
    
    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(port);
    dest.sin6_addr = ip;
    if (IN6_IS_ADDR_LINKLOCAL(&dest.sin6_addr)) {
        dest.sin6_scope_id = global_iface_index;  // Spécifier l'index de l'interface
    }
    
    SSL_set_fd(ssl, socket_tcp_client);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(socket_tcp);
        return -1;  // Erreur de connexion
    }

    // Envoi du message 5 : ID, IP, PORT, PUBLIC_KEY
    uint8_t msg[21 + crypto_sign_PUBLICKEYBYTES];
    if (msg_5(msg, id_peer, port_tcp, my_pubkey) != 0) {
        printf("Erreur lors de la construction du message.\n");
        close(socket_tcp);
        return -1;
    }
    
    SSL_write(ssl, msg, sizeof(msg));
    printf("Message 5 envoyé : ID=%u, IP=%s, PORT=%u\n", id_peer, port_tcp);

    close(socket_tcp_client);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;  // Retourne le résultat de la connexion
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
