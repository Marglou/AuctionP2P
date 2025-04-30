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
#include <ifaddrs.h>

#include "../include/peer.h"
#include "../include/superviseur.h"
#include "../include/enchere.h"
#include "../include/message.h"
#include "../include/connexion.h"


EnchereSocket encheres[MAX_ENCHERES];
int nb_encheres = 0;    // Nombre d'enchères rejointes
int enchere_active = -1; // Index dans encheres[]
int cpt = 0 ; // Compteur pour les enchères qu'il a initié
char id_peer[128]; // ID du pair

int global_sock = -1;
char nom[100];
int global_iface_index = 0;

int socket_tcp = -1; // Socket TCP pour la connexion
int port_tcp = -1; // Port TCP pour la connexion
struct tcp_listener_state listener_tcp = {0};

struct peer_info discovered_peers[MAX_PEERS];
size_t num_peers = 0;

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
    close(socket_tcp);
    for (int i = 0; i < nb_encheres; i++) {
        close(encheres[i].sock);
    }

    exit(0);
}

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

            // Gestion des messages binaires avec code
            uint8_t code = (uint8_t)buffer[0];

            // ###############################################
            // Protocole pour rejoindre un système d'enchères
            // ###############################################
            if (code == 3 && len == 3 && nb_encheres > 0) { // CODE 3 : recoit demande pour rejoindre un système d'enchère
                uint16_t port_tcp_dest;
                memcpy(&port_tcp_dest, &buffer[1], 2);  // Extraire le port du message reçu

                char ip_str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &src.sin6_addr, ip_str, sizeof(ip_str));  // Convertir l'adresse IP en chaîne
                
                // Création de la structure sockaddr_in6 pour la connexion TCP
                struct sockaddr_in6 dest_tcp = {0};
                dest_tcp.sin6_family = AF_INET6;
                dest_tcp.sin6_port = htons(ntohs(port_tcp_dest));  // Utiliser le port du serveur
                dest_tcp.sin6_addr = src.sin6_addr;  // Utiliser l'adresse IP du pair
                
                if (IN6_IS_ADDR_LINKLOCAL(&src.sin6_addr)) {
                    dest_tcp.sin6_scope_id = global_iface_index;  // Spécifier l'index de l'interface
                }

                // Créer un socket TCP
                int sock = socket(AF_INET6, SOCK_STREAM, 0);
                if (sock < 0) {
                    perror("socket");
                    return NULL;
                }
                
                // Connexion au serveur
                if (connect(sock, (struct sockaddr *)&dest_tcp, sizeof(dest_tcp)) == 0) {
                   // Si la connexion est réussie, envoyer le message CODE 4
                    uint8_t msg[21];  // 1 + 2 + 16 + 2 = 21 octets
                    if (msg_4(msg, id_peer, port_tcp) != 0) {
                        fprintf(stderr, "Erreur lors de la construction du message.\n");
                        return NULL;
                    }

                    // Envoi
                    send(sock, msg, sizeof(msg), 0);
                    printf("Réponse envoyée\n");
                    close(sock);  // Fermer le socket après l'envoi

                } else {
                    perror("connect TCP");
                    close(sock);  // Fermer le socket en cas d'échec
                }
                
            }


            // Traitement texte normal
            printf("%s", buffer);
            fflush(stdout);

            if (strncmp(buffer, "[VALIDATION]", 12) == 0) {
                char *msg = strchr(buffer, ' ') + 1;
                char *sig_str = strchr(msg, ' ') + 1;
                unsigned char sig[EVP_PKEY_size(my_privkey)];
                size_t siglen = strlen(sig_str) / 2;
                for (size_t i = 0; i < siglen; i++) {
                    sscanf(sig_str + 2 * i, "%2hhx", &sig[i]);
                }

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

    // socket TCP
    socket_tcp = create_tcp_socket_serveur();
    if (socket_tcp < 0) {
        fprintf(stderr, "Erreur lors de la création du socket TCP.\n");
        exit(EXIT_FAILURE);
    }

    // État du listener TCP
    listener_tcp.socket_tcp = socket_tcp;
    listener_tcp.response_received = false;
    listener_tcp.first_response_time = 0;
    
    pthread_t tcp_thread;
    pthread_create(&tcp_thread, NULL, listen_tcp_thread, &listener_tcp);
    


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

        else if (strcmp(buffer, "join\n") == 0) {
            // char auction_groupe[INET6_ADDRSTRLEN];
            // char auction_id[64];
            // if (sscanf(buffer + 10, "%s %s", auction_id, auction_groupe) == 2) {
            //     join_enchere(auction_id, auction_groupe);
            // }

            if (msg_join_enchere() == -1) {
                printf("Erreur lors de l'envoi de la demande de rejoindre l'enchère.\n");
            } else {
                // printf("Demande de rejoindre un système d’enchères envoyée (CODE 3).\n");

            }
        }
        
        else {
            char msg[BUF_SIZE];
            snprintf(msg, sizeof(msg), "[%s] %s", nom, buffer);
            if (strlen(msg) >= sizeof(msg)) {
                fprintf(stderr, "Erreur : le message est trop long pour le tampon.\n");
            }
            
                // printf("enchere  : %d\n", nb_encheres);
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
    close(socket_tcp);
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



// ------------------- TCP ------------------------------------------

int generate_random_port() {
    // Initialiser le générateur de nombres aléatoires
    srand(time(NULL));  
    int MIN_PORT = 1024; // Port minimum
    int MAX_PORT = 65535; // Port maximum
    
    // Générer un port aléatoire entre MIN_PORT et MAX_PORT
    return (rand() % (MAX_PORT - MIN_PORT + 1)) + MIN_PORT;
}

int create_tcp_socket_serveur() {
    int sock = socket(PF_INET6, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket TCP");
        return -1;
    }

    port_tcp = generate_random_port();

    struct sockaddr_in6 addr = {0};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port_tcp); 
    addr.sin6_addr = in6addr_any;

    if (IN6_IS_ADDR_LINKLOCAL(&addr.sin6_addr)) {
        addr.sin6_scope_id = global_iface_index;
    }

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind TCP");
        close(sock);
        return -1;
    }

    if (listen(sock, 5) < 0) {
        perror("listen TCP");
        close(sock);
        return -1;
    }

    return sock;
}

int create_tcp_socket_client(const char *ip_dest, int port_dest) {
    int sock = socket(PF_INET6, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket TCP");
        return -1;
    }

    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    inet_pton(AF_INET6, ip_dest, &dest.sin6_addr);
    dest.sin6_port = htons(port_dest);
    if (IN6_IS_ADDR_LINKLOCAL(&dest.sin6_addr)) {
        dest.sin6_scope_id = global_iface_index;
    }

    if (connect(sock, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("connect TCP");
        close(sock);
        return -1;
    }

    return sock;
}


int get_adresse_perso_par_index(struct in6_addr *addr, unsigned int iface_index) {
    struct ifaddrs *ifaddr, *ifa;
    
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET6)
            continue;

        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;

        // Vérifie que c'est la bonne interface par son index
        if (if_nametoindex(ifa->ifa_name) == iface_index) {
            memcpy(addr, &sin6->sin6_addr, sizeof(struct in6_addr));
            freeifaddrs(ifaddr);
            return 0;
        }
    }

    freeifaddrs(ifaddr);
    fprintf(stderr, "Adresse perso non trouvée pour index %u\n", iface_index);
    return -1;
}
