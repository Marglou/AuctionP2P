#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/socket.h>

#include "../include_2/peer.h"

#define PORT 12345
#define GROUP "ff15::abcd"
#define BUF_SIZE 1024

#define PORT_ENCHERE 12346
#define GROUP_ENCHERE "ff15::efgh"

static int global_sock = -1;
static char global_nom[100];
static int global_iface_index = 0;

// Gestion de la déconnexion propre avec Ctrl+C
void handle_sigint(int sig)
{
    char leave_msg[BUF_SIZE];
    snprintf(leave_msg, sizeof(leave_msg), "[LEAVE] %s a quitté le groupe.\n", global_nom);

    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(PORT);
    inet_pton(AF_INET6, GROUP, &dest.sin6_addr);
    dest.sin6_scope_id = global_iface_index;

    sendto(global_sock, leave_msg, strlen(leave_msg), 0,
           (struct sockaddr *)&dest, sizeof(dest));

    close(global_sock);
    exit(0);
}

// Thread de réception
void *peer_receiver(void *arg)
{
    int sock = *(int *)arg;
    char buffer[BUF_SIZE];
    struct sockaddr_in6 src;
    socklen_t srclen = sizeof(src);

    while (1)
    {
        ssize_t len = recvfrom(sock, buffer, BUF_SIZE - 1, 0,
                               (struct sockaddr *)&src, &srclen);

        if (len > 0)
        {
            buffer[len] = '\0';
            printf("%s", buffer);
            fflush(stdout);
        }
    }
    return NULL;
}

// Démarrage du pair
void peer_start(const char *nom, const char *interface)
{
    int iface_index = if_nametoindex(interface);
    if (iface_index == 0)
    {
        perror("if_nametoindex");
        exit(EXIT_FAILURE);
    }

    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in6 addr = {0};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(PORT);
    addr.sin6_addr = in6addr_any;
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    struct ipv6_mreq mreq;
    inet_pton(AF_INET6, GROUP, &mreq.ipv6mr_multiaddr);
    mreq.ipv6mr_interface = iface_index;
    setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq));

    // Infos globales pour SIGINT
    strncpy(global_nom, nom, sizeof(global_nom));
    global_iface_index = iface_index;
    global_sock = sock;

    signal(SIGINT, handle_sigint);

    // Notifier les autres de la connexion
    char join_msg[BUF_SIZE];
    snprintf(join_msg, sizeof(join_msg), "[JOIN] %s a rejoint le groupe.\n", nom);

    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(PORT);
    inet_pton(AF_INET6, GROUP, &dest.sin6_addr);
    dest.sin6_scope_id = iface_index;

    sendto(sock, join_msg, strlen(join_msg), 0,
           (struct sockaddr *)&dest, sizeof(dest));

    // Thread récepteur
    pthread_t tid;
    pthread_create(&tid, NULL, peer_receiver, &sock);

    // Envoi des messages
    char buffer[BUF_SIZE];
    while (fgets(buffer, sizeof(buffer), stdin))
    {

        if (strcmp(buffer, "lancer\n") == 0)
        {
            creer_enchere();
        }
        else if (strncmp(buffer, "rejoindre ", 10) == 0) {
            char auction_groupe[INET6_ADDRSTRLEN];
            char auction_id[64];
            if (sscanf(buffer + 10, "%s %s", auction_id, auction_groupe) == 2) {
                join_enchere(auction_id, auction_groupe);
            }
            // join_enchere(auction_id, auction_groupe);   
        }
        
        else
        {
            char msg[BUF_SIZE];
            snprintf(msg, sizeof(msg), "%s: %s", nom, buffer);

            sendto(sock, msg, strlen(msg), 0,
                   (struct sockaddr *)&dest, sizeof(dest));
        }
    }

    close(sock);
}


void creer_enchere()
{
    char auction_group[INET6_ADDRSTRLEN];
    char auction_id[64];

    // Générer une adresse d'enchère unique (ici exemple simple)
    snprintf(auction_id, sizeof(auction_id), "auction-%x", rand());
    snprintf(auction_group, sizeof(auction_group), "ff15::%x", rand());

    // printf("Nouvelle enchère créée ! ID: %s, Groupe: %s\n", auction_id, auction_group);

    int iface_index = if_nametoindex("eth0");
    if (iface_index == 0)
    {
        perror("if_nametoindex");
        exit(EXIT_FAILURE);
    }

    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in6 addr = {0};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(PORT_ENCHERE);
    addr.sin6_addr = in6addr_any;
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    struct ipv6_mreq mreq;
    inet_pton(AF_INET6, auction_group, &mreq.ipv6mr_multiaddr);
    mreq.ipv6mr_interface = iface_index;
    setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq));

    // Message à tous les pairs via l'adresse de liaison
    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(PORT);
    inet_pton(AF_INET6, GROUP, &dest.sin6_addr); // liaison_group = adresse globale
    dest.sin6_scope_id = iface_index;

    char msg[BUF_SIZE];
    snprintf(msg, sizeof(msg), "[NEW_AUCTION] ID=%s GROUPE=%s \n", auction_id, auction_group);
    sendto(sock, msg, strlen(msg), 0, (struct sockaddr *)&dest, sizeof(dest));
}


// Thread pour recevoir les messages du groupe d'enchères
void *auction_receiver(void *arg)
{
    int sock = *(int *)arg;
    char buffer[BUF_SIZE];
    struct sockaddr_in6 src;
    socklen_t srclen = sizeof(src);

    while (1)
    {
        ssize_t len = recvfrom(sock, buffer, BUF_SIZE - 1, 0,
                               (struct sockaddr *)&src, &srclen);

        if (len > 0)
        {
            buffer[len] = '\0';
            printf("[Enchère] %s", buffer);
            fflush(stdout);
        }
    }
    return NULL;
}

void join_enchere ( char *auction_id, char *auction_group) {


    int iface_index = if_nametoindex("eth0");
    if (iface_index == 0)
    {
        perror("if_nametoindex");
        exit(EXIT_FAILURE);
    }

    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in6 addr = {0};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(PORT_ENCHERE);
    addr.sin6_addr = in6addr_any;
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    struct ipv6_mreq mreq;
    inet_pton(AF_INET6, auction_group, &mreq.ipv6mr_multiaddr);
    mreq.ipv6mr_interface = iface_index;
    setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq));

    // Thread récepteur pour le groupe d'enchères
    pthread_t auction_tid;
    pthread_create(&auction_tid, NULL, auction_receiver, &sock);

    // Message à tous les pairs via l'adresse de liaison
    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(PORT_ENCHERE);
    inet_pton(AF_INET6, GROUP_ENCHERE, &dest.sin6_addr); // 
    dest.sin6_scope_id = iface_index;

    char msg[BUF_SIZE];
    snprintf(msg, sizeof(msg), "a rejoint l'enchere  ID=%s ADDR=%s", auction_id, auction_group);
    sendto(sock, msg, strlen(msg), 0, (struct sockaddr *)&dest, sizeof(dest));
}