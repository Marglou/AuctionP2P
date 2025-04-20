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
#include <asm-generic/socket.h>
#include <openssl/sha.h>


#include "../include_2/peer.h"

#define PORT 12365
#define GROUP "ff15::abcd"
#define BUF_SIZE 1024

#define PORT_ENCHERE 12366

EnchereSocket encheres[MAX_ENCHERES];
int nb_encheres = 0;    // Nombre d'enchères rejointes
int enchere_active = -1; // Index dans encheres[]
int cpt = 0 ; // Compteur pour les enchères qu'il a inité
char id_peer[128]; // ID du pair

static int global_sock = -1;
static char nom[100];
static int global_iface_index = 0;


// Gestion de la déconnexion propre avec Ctrl+C
void handle_sigint(int sig)
{
    // utiliser sig pour enlever les warnings
    (void)sig;
    char leave_msg[BUF_SIZE];
    snprintf(leave_msg, sizeof(leave_msg), "[LEAVE] %s a quitté le groupe.\n", nom);

    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(PORT);
    inet_pton(AF_INET6, GROUP, &dest.sin6_addr);
    dest.sin6_scope_id = global_iface_index;

    sendto(global_sock, leave_msg, strlen(leave_msg), 0,
           (struct sockaddr *)&dest, sizeof(dest));

    close(global_sock);
    for (int i = 0; i < nb_encheres; i++) {
        close(encheres[i].sock);
    }

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

    // Générer l'ID du pair
    char ipv6_perso[INET6_ADDRSTRLEN];
    snprintf(ipv6_perso, sizeof(ipv6_perso), "fe80::%x", iface_index);
    generer_id_peer(nom, ipv6_perso);

    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));

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
        }
        
        else {
            char msg[BUF_SIZE];
            snprintf(msg, sizeof(msg), "[%s] %s", nom, buffer);
            if (strlen(msg) >= sizeof(msg)) {
                fprintf(stderr, "Erreur : le message est trop long pour le tampon.\n");
            }
            
                printf("enchere active : %d\n", enchere_active);
                if (enchere_active >= 0) {
                struct sockaddr_in6 dest = {0};
                dest.sin6_family = AF_INET6;
                dest.sin6_port = htons(PORT_ENCHERE);
                inet_pton(AF_INET6, encheres[enchere_active].group, &dest.sin6_addr);
                dest.sin6_scope_id = global_iface_index;
        
                sendto(encheres[enchere_active].sock, msg, strlen(msg), 0,
                       (struct sockaddr *)&dest, sizeof(dest));

            } else {
                struct sockaddr_in6 dest = {0};
                dest.sin6_family = AF_INET6;
                dest.sin6_port = htons(PORT);
                inet_pton(AF_INET6, GROUP, &dest.sin6_addr);
                dest.sin6_scope_id = global_iface_index;
        
                sendto(global_sock, msg, strlen(msg), 0,
                       (struct sockaddr *)&dest, sizeof(dest));
            }
        }
        
    }

    close(sock);

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
    // Envoi du message NEW_AUCTION à tous les pairs
    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(PORT);
    if (inet_pton(AF_INET6, GROUP, &dest.sin6_addr) != 1) {
        perror("inet_pton (liaison group)");
        exit(EXIT_FAILURE);
    }
    dest.sin6_scope_id = global_iface_index;

    char msg[BUF_SIZE];
    snprintf(msg, sizeof(msg), "[NEW_AUCTION] ID=%s GROUPE=%s\n", auction_id, auction_group);

    // On utilise le socket global pour l’annonce
    if (sendto(global_sock, msg, strlen(msg), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto");
    }

    // Le créateur rejoint lui-même l’enchère
    join_enchere(auction_id, auction_group);

    printf("Vous avez lancé et rejoint une nouvelle enchère : %s (%s)\n", auction_id, auction_group);
    cpt++ ; // Incrémente le compteur d'enchères initiées
}



// Thread pour recevoir les messages du groupe d'enchères
void *auction_receiver(void *arg)
{
    int sock = *(int *)arg;
    free(arg); // Libère la mémoire allouée dynamiquement

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


void join_enchere(const char *id, const char *group)
{
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

    nb_encheres++;
}

void generer_id_peer(const char *nom, char *ipv6_perso) {
    struct in6_addr addr;
    // Conversion de l'adresse IPv6 en structure in6_addr
    if (inet_pton(AF_INET6, ipv6_perso, &addr) != 1) {
        perror("inet_pton");
        return;
    }

    // Utiliser les 4 premiers octets de l'adresse IPv6 pour créer une valeur
    unsigned int ipv6_part = 0;
    for (int i = 0; i < 4; i++) {
        ipv6_part = (ipv6_part << 8) | addr.s6_addr[i];
    }

    srand(time(NULL)); // Initialiser le générateur de nombres aléatoires
    // Générer un ID basé sur l'adresse et le nom
    snprintf(id_peer, sizeof(id_peer), "%s-%x%d", nom, ipv6_part, rand() % 1000);
}


