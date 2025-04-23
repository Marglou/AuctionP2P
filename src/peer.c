//peer.c
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
#include <openssl/evp.h>
#include <openssl/err.h>


#include "../include/peer.h"
#include "../include/superviseur.h"
#include "../include/enchere.h"

#define PORT 12365
#define GROUP "ff15::abcd"
#define BUF_SIZE 1024

#define PORT_ENCHERE 12366

AdressePerso mon_adresse_perso;
EnchereSocket encheres[MAX_ENCHERES];
int nb_encheres = 0;    // Nombre d'enchères rejointes
int enchere_active = -1; // Index dans encheres[]
int cpt = 0 ; // Compteur pour les enchères qu'il a inité
char id_peer[128]; // ID du pair

int global_sock = -1;
char nom[100];
int global_iface_index = 0;

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
void *peer_receiver(void *arg){
    int sock = *(int *)arg;
    char buffer[BUF_SIZE];
    struct sockaddr_in6 src;
    socklen_t srclen = sizeof(src);

    while (1){
        ssize_t len = recvfrom(sock, buffer, BUF_SIZE - 1, 0,
                               (struct sockaddr *)&src, &srclen);

        if (len > 0){
            buffer[len] = '\0';
            printf("%s", buffer);
            fflush(stdout);

            if (strncmp(buffer, "[VALIDATION]", 12) == 0) {
                // Extraire le message et la signature
                char *msg = strchr(buffer, ' ') + 1;
                char *sig_str = strchr(msg, ' ') + 1;
                unsigned char sig[EVP_PKEY_size(my_privkey)];
                size_t siglen = strlen(sig_str) / 2;
                for (size_t i = 0; i < siglen; i++) {
                    sscanf(sig_str + 2 * i, "%2hhx", &sig[i]);
                }

                // Vérifier la signature avec la clé publique du pair
                EVP_PKEY *peer_pubkey = get_peer_pubkey(nom);
                if (peer_pubkey && verify_message(peer_pubkey, (unsigned char *)msg, strlen(msg), sig, siglen)) {
                    printf("Message validé par %s\n", nom);
                } else {
                    printf("Échec de la vérification du message de %s\n", nom);
                }
            }
        }
    }
    return NULL;
}

// Démarrage du pair
void peer_start(const char *nom, const char *interface){
    int iface_index = if_nametoindex(interface);
    if (iface_index == 0){
        perror("if_nametoindex");
        exit(EXIT_FAILURE);
    }

    // Générer l'ID du pair
    char ipv6_perso[INET6_ADDRSTRLEN];
    snprintf(ipv6_perso, sizeof(ipv6_perso), "fe80::%x", iface_index);
    generer_id_peer(nom, ipv6_perso);
    creer_adresse_perso(PORT, PORT + 1, iface_index); 


    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0){
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
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0){
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
    while (fgets(buffer, sizeof(buffer), stdin)){

        if (strcmp(buffer, "lancer\n") == 0){
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


void creer_adresse_perso(int port_udp, int port_tcp, int iface_index) {
    char ipv6_str[INET6_ADDRSTRLEN];
    snprintf(ipv6_str, sizeof(ipv6_str), "fe80::%x", iface_index);  // adresse lien-local fictive

    if (inet_pton(AF_INET6, ipv6_str, &mon_adresse_perso.addr) != 1) {
        perror("inet_pton");
        exit(EXIT_FAILURE);
    }

    mon_adresse_perso.port_udp = port_udp;
    mon_adresse_perso.port_tcp = port_tcp;
}
