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
#include <openssl/ssl.h>
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
                    uint16_t peer_id = atoi(id_peer);
                    if (msg_4(msg, peer_id, port_tcp) != 0) {
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
                // printf("Demande de rejoindre un système d'enchères envoyée (CODE 3).\n");

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

// Function to connect to all other peers and send message 6
int connect_to_peers_and_send_info(struct peer *p, uint16_t new_peer_id, struct in6_addr new_peer_ip, 
                                 uint16_t new_peer_port, unsigned char *new_peer_cle) {
    int ret = 0;
    struct peer *current = p->next;
    
    while (current != p) {
        // Create TLS connection to the peer
        int sock = connexion_TLS(current->ip, current->port_tcp);
        if (sock < 0) {
            fprintf(stderr, "Failed to create TLS connection to peer %d\n", current->id);
            current = current->next;
            continue;
        }

        // Create and send message 6
        uint8_t msg[1 + 2 + 16 + 2 + 113];  // CODE + ID + IP + PORT + CLE
        int msg_len = msg_6(msg, new_peer_id, new_peer_ip, new_peer_port, new_peer_cle);
        
        if (send(sock, msg, msg_len, 0) != msg_len) {
            fprintf(stderr, "Failed to send message 6 to peer %d\n", current->id);
            close(sock);
            current = current->next;
            continue;
        }

        // Read response
        uint8_t response[2];
        int bytes_read = recv(sock, response, 2, 0);
        if (bytes_read != 2) {
            fprintf(stderr, "Failed to read response from peer %d\n", current->id);
            close(sock);
            current = current->next;
            continue;
        }

        close(sock);
        current = current->next;
    }

    return ret;
}

// Function to handle a new peer connection (message 5)
int handle_new_peer(struct peer *p, SSL *ssl, uint8_t *msg, size_t msg_len) {
    struct message_5 msg_struct;
    if (parse_msg_5(msg, msg_len, &msg_struct) != 0) {
        return -1;
    }

    // Check if ID is already taken
    uint16_t assigned_id = msg_struct.id;
    if (find_peer_id(p, &assigned_id, false)) {
        // Send error response (code 51)
        uint8_t response[1] = {51};
        SSL_write(ssl, response, 1);
        return -1;
    }

    // Send success response with assigned ID (code 50)
    uint8_t response[3] = {50, (assigned_id >> 8) & 0xFF, assigned_id & 0xFF};
    SSL_write(ssl, response, 3);

    // Connect to all other peers and send the new peer's information
    if (connect_to_peers_and_send_info(p, assigned_id, msg_struct.ip, 
                                     msg_struct.port, msg_struct.cle) != 0) {
        return -1;
    }

    // Add the new peer to our list
    return add_peer(p, assigned_id, msg_struct.ip, msg_struct.port, msg_struct.cle);
}

int find_peer_id(struct peer *p, uint16_t *id, bool find_free) {
    if (!p || !id) return -1;

    // If we're checking if an ID is taken
    if (!find_free) {
        struct peer *current = p->next;
        while (current != p) {
            if (current->id == *id) {
                return 1; // ID is taken
            }
            current = current->next;
        }
        return 0; // ID is free
    }

    // If we're looking for a free ID
    uint16_t start_id = 1;
    uint16_t end_id = 65535;
    
    // First try the requested ID if provided
    if (*id != 0) {
        if (!find_peer_id(p, id, false)) {
            return 0; // Requested ID is free
        }
        start_id = *id + 1;
    }

    // Search for a free ID
    for (uint16_t test_id = start_id; test_id <= end_id; test_id++) {
        if (!find_peer_id(p, &test_id, false)) {
            *id = test_id;
            return 0;
        }
    }

    return -1; // No free ID found
}

int add_peer(struct peer *p, uint16_t id, struct in6_addr ip, uint16_t port, unsigned char *cle) {
    if (!p || !cle) return -1;

    // Check if ID is available
    if (find_peer_id(p, &id, false) == 1) {
        // ID is taken, find a free one
        if (find_peer_id(p, &id, true) != 0) {
            return -1; // No free ID found
        }
    }

    struct peer *new_peer = malloc(sizeof(struct peer));
    if (!new_peer) {
        return -1;
    }

    new_peer->id = id;
    new_peer->ip = ip;
    new_peer->port_tcp = port;
    memcpy(new_peer->cle, cle, 113);

    // Insert at the beginning of the list
    new_peer->next = p->next;
    p->next = new_peer;

    return 0;
}
