// enchere.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
//#include <asm-generic/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <net/if.h>

#include "../include/enchere.h"
#include "../include/superviseur.h"
#include "../include/peer.h"
#include "../include/message.h"
#include "../include/connexion.h"

#define IFACE_NAME "enp0s3"


void print_enchere(const EnchereSocket *e) {
    char addr_buf[INET6_ADDRSTRLEN];

    // Conversion de l'adresse IPv6 binaire en chaîne lisible
    if (inet_ntop(AF_INET6, &(e->group), addr_buf, sizeof(addr_buf)) == NULL) {
        perror("inet_ntop");
        return;
    }

    printf("=== Enchère ===\n");
    printf("ID: %d\n", e->id_enchere);
    printf("Port: %d\n", e->port_enchere);
    printf("Groupe multicast: %s\n", addr_buf);
    printf("Socket: %d\n", e->sock);
    printf("Nombre de pairs: %d\n", e->nb_pairs);
}

int join_enchere(int id, char *group, uint16_t port)
{
    if (nb_encheres >= MAX_ENCHERES)
    {
        fprintf(stderr, "Nombre maximum d'enchères atteint.\n");
        return -1;
    }

    for (int i = 0; i < nb_encheres; i++)
    {
        if (encheres[i].id_enchere == id)
        {
            fprintf(stderr, "Vous êtes déjà dans l'enchère %d.\n", id);
            return -1;
        }
    }

    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("socket enchere");
        return -1;
    }

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(port);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind enchere");
        close(sock);
        return -1;
    }

    // Get the interface index
    int if_index = if_nametoindex(IFACE_NAME);
    if (if_index == 0) {
        perror("if_nametoindex");
        close(sock);
        return -1;
    }

    // Abonnement au groupe multicast
    struct ipv6_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    
    // Convert the multicast address
    if (inet_pton(AF_INET6, group, &mreq.ipv6mr_multiaddr) != 1)
    {
        perror("inet_pton (group enchere)");
        close(sock);
        return -1;
    }

    // Debug print the multicast address
    char addr_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &mreq.ipv6mr_multiaddr, addr_str, sizeof(addr_str));
    printf("Debug - Converted multicast address: %s\n", addr_str);

    // Verify this is a valid multicast address
    if (!IN6_IS_ADDR_MULTICAST(&mreq.ipv6mr_multiaddr)) {
        fprintf(stderr, "Invalid multicast address: %s\n", addr_str);
        close(sock);
        return -1;
    }

    // Set the interface index
    mreq.ipv6mr_interface = if_index;

    printf("Debug - Joining multicast group %s on interface %s (index %d)\n", 
           addr_str, IFACE_NAME, if_index);

    if (setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) < 0)
    {
        perror("setsockopt (join group enchere)");
        close(sock);
        return -1;
    }

    // Sauvegarde dans le tableau
    encheres[nb_encheres].id_enchere = id;
    encheres[nb_encheres].port_enchere = port;
    encheres[nb_encheres].sock = sock;
    memcpy(&encheres[nb_encheres].group, &mreq.ipv6mr_multiaddr, sizeof(struct in6_addr));

    enchere_active = nb_encheres;

    int *sock_ptr = malloc(sizeof(int));
    if (!sock_ptr)
    {
        perror("malloc");
        close(sock);
        return -1;
    }
    *sock_ptr = sock;

    pthread_t tid;
    if (pthread_create(&tid, NULL, auction_receiver, sock_ptr) != 0)
    {
        perror("pthread_create");
        free(sock_ptr);
        close(sock);
        return -1;
    }

    // Construire l'adresse du groupe pour envoyer un message
    struct sockaddr_in6 group_addr = {0};
    group_addr.sin6_family = AF_INET6;
    group_addr.sin6_port = htons(port);
    memcpy(&group_addr.sin6_addr, &mreq.ipv6mr_multiaddr, sizeof(struct in6_addr));
    group_addr.sin6_scope_id = if_index;

    // Message d'acceptation
    char accept_msg[BUF_SIZE];
    snprintf(accept_msg, sizeof(accept_msg), "[ACCEPTED] Vous avez rejoint l'enchère %d\n", id);
    if (sendto(sock, accept_msg, strlen(accept_msg), 0, (struct sockaddr *)&group_addr, sizeof(group_addr)) < 0)
    {
        perror("sendto (accept message)");
        close(sock);
        return -1;
    }

    printf("Vous avez rejoint l'enchère %d sur %s\n", id, addr_str);
    nb_encheres++;
    return 0;
}


void creer_enchere()
{
    if (nb_encheres >= MAX_ENCHERES) {
        fprintf(stderr, "Le nombre maximum d'enchères a été atteint.\n");
        return;
    }

    if (is_superviseur == 1) {
        printf("Deja superviseur d'une enchere\n");
        return;
    }

    char auction_group[INET6_ADDRSTRLEN];

    int auction_num_id = id_peer * 100 + (cpt + 1);
    // Generate a random multicast address in the ff15::/16 range
    int r = rand() & 0xFFFF; // max 4 chiffres hexadécimaux
    snprintf(auction_group, sizeof(auction_group), "ff15::%04x", r); // Ensure 4 hex digits with leading zeros

    // Debug print the generated multicast address
    printf("Debug - Generated multicast address: %s\n", auction_group);

    enchere_active++;
    encheres[enchere_active].id_enchere = auction_num_id;
    
    // Convert and validate the multicast address
    struct in6_addr group_addr;
    if (inet_pton(AF_INET6, auction_group, &group_addr) != 1) {
        fprintf(stderr, "Erreur : adresse IPv6 invalide: %s\n", auction_group);
        return;
    }

    // Verify this is a valid multicast address
    if (!IN6_IS_ADDR_MULTICAST(&group_addr)) {
        fprintf(stderr, "Erreur : adresse générée n'est pas une adresse multicast valide: %s\n", auction_group);
        return;
    }

    // Store the multicast address
    memcpy(&encheres[enchere_active].group, &group_addr, sizeof(struct in6_addr));

    // Generate a random port for the auction
    uint16_t port_enchere = generate_random_port();
    encheres[enchere_active].port_enchere = port_enchere;

    // Create and send message 8 (auction initiation)
    uint8_t msg[1 + 2 + 4 + 4]; // CODE + ID + NUMV + PRIX
    msg[0] = 8; // CODE = 8 for auction initiation
    uint16_t peer_id = auction_num_id;
    uint32_t numv = cpt + 1;
    printf("Entrez le prix de départ de l'enchère : ");
    uint32_t initial_price = 0;
    if (scanf("%d", &initial_price) != 1) {
        fprintf(stderr, "Erreur : entrée invalide pour le prix.\n");
    }
    
    if(msg_8(msg, peer_id, numv, initial_price) != 11) {
        printf("Erreur message 8");
    }

    // Join the auction group first
    if (join_enchere(auction_num_id, auction_group, port_enchere) != 0) {
        fprintf(stderr, "Erreur lors de la création de l'enchère.\n");
        return;
    }

    // Send the message to the auction group
    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(encheres[enchere_active].port_enchere);
    memcpy(&dest.sin6_addr, &encheres[enchere_active].group, sizeof(struct in6_addr));
    dest.sin6_scope_id = global_iface_index;

    sendto(encheres[enchere_active].sock, msg, sizeof(msg), 0,
           (struct sockaddr *)&dest, sizeof(dest));

    printf("Enchère initiée : ID=%d, NUMV=%u, PRIX=%u\n", auction_num_id, numv, initial_price);
    cpt++; // Incrémente le compteur d'enchères initiées
    is_superviseur = 1;
    enchere_supervise = auction_num_id;
}


int msg_join_enchere()
{
    const int timeout_sec = 3;
    const int max_attempts = 3;

    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(PORT);
    inet_pton(AF_INET6, GROUP, &dest.sin6_addr);
    dest.sin6_scope_id = global_iface_index;

    int attempts = 0;
    time_t start = time(NULL);

    while (attempts++ < max_attempts && listener_tcp.response_received == 0)
    {
        printf("Reponse recue %d\n", listener_tcp.response_received);
        printf("Tentative %d : envoi du message CODE 3.\n", attempts);
        uint8_t msg[3] = {3};
        uint16_t port_tcp_net = htons(port_tcp);
        memcpy(&msg[1], &port_tcp_net, 2);

        sendto(global_sock, msg, sizeof(msg), 0, (struct sockaddr *)&dest, sizeof(dest));
        sleep(timeout_sec);
    }

    if (num_peers > 0)
    {
        struct peer_info *peer_Q = &discovered_peers[0];
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &peer_Q->ip, ip_str, sizeof(ip_str));
        uint16_t port = ntohs(peer_Q->port_tcp);
        printf("Connexion à : ID=%u, IP=%s, PORT=%u\n", peer_Q->id, ip_str, port);

        // Connexion au pair 
        // connexion qui doit rester ouverte, stocker le return de x=connexion_TLS et voir comment gerer ca
        int socket_P = connexion_TLS(peer_Q->ip, port);
        if (socket_P < 0){
            close(socket_P);
            printf("Erreur connexion à Q\n");
            return -1;
        }

        printf("Je suis ds msg_join étape 7\n");

        // RECEVOIR MESSAGE 7
        uint8_t buffer[1024];
        memset(buffer, 0, sizeof(buffer));
        ssize_t len = recv(socket_P, buffer, sizeof(buffer) - 1, 0);
        if (len <= 0)
        {
            perror("recv");
            close(socket_P);
            return -1;
        }
        buffer[len] = '\0';
        printf("Message reçu 7\n");
        // struct message_7 msg7;
        // printf("indice de l'enchere active %d\n", enchere_active);
        enchere_active++;
        // printf("num de parse msg7 %d\n",decode_message_7(buffer, len, &encheres[enchere_active]));
        // if (decode_message_7(buffer, len) != 0)
        // {
        //     fprintf(stderr, "Erreur lors du parsing du message 7.\n");
        //     close(socket_P);
        //     return -1;
        // }
        decode_message_7(buffer, len);
        printf("Message 7 reçu : ID_Q=, IP_enchere=, PORT_enchere\n");
        close(socket_P);

        // Print the decoded message details
        char str_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &encheres[enchere_active].group, str_ip, sizeof(str_ip));
        printf("Message 7 reçu : ID_Q=%d, IP_enchere=%s, PORT_enchere=%d\n", 
               encheres[enchere_active].id_enchere,
               str_ip,
               encheres[enchere_active].port_enchere);

        close(socket_P);

        // Join the auction with the received information
        if (join_enchere(encheres[enchere_active].id_enchere, 
                        str_ip, 
                        encheres[enchere_active].port_enchere) != 0) {
            fprintf(stderr, "Erreur lors de la jointure de l'enchère.\n");
            return -1;
        }
        return 0;
    }

    printf("Aucune enchère trouvée. Création d'une nouvelle.\n");
    creer_enchere();
    return -1;
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
        memset(buffer, 0, BUF_SIZE);
        ssize_t len = recvfrom(sock, buffer, BUF_SIZE - 1, 0,
                               (struct sockaddr *)&src, &srclen);

        if (len > 0)
        {
            buffer[len] = '\0';
            
            // Handle binary messages with codes
            uint8_t code = (uint8_t)buffer[0];
            
            switch (code) {
                case 8: { // Auction initiation
                    uint16_t id = ntohs(*(uint16_t*)&buffer[1]);
                    uint32_t numv = ntohl(*(uint32_t*)&buffer[3]);
                    uint32_t prix = ntohl(*(uint32_t*)&buffer[7]);
                    
                    printf("[Enchère] Nouvelle enchère initiée par pair %u: NUMV=%u, PRIX=%u\n", 
                           id, numv, prix);
                    break;
                }
                
                case 9: { // Bid message
                    uint16_t id = ntohs(*(uint16_t*)&buffer[1]);
                    uint32_t numv = ntohl(*(uint32_t*)&buffer[3]);
                    uint32_t prix = ntohl(*(uint32_t*)&buffer[7]);
                    
                    printf("[Enchère] Nouvelle offre de pair %u: NUMV=%u, PRIX=%u\n", 
                           id, numv, prix);
                    
                    // If we are the supervisor, relay the message with code 10
                    /*if (enchere_active >= 0 && encheres[enchere_active].id == id_peer) {
                        uint8_t relay_msg[1 + 2 + 4 + 4];
                        relay_msg[0] = 10; // Change code to 10
                        memcpy(&relay_msg[1], &buffer[1], 10); // Copy ID, NUMV, and PRIX
                        
                        struct sockaddr_in6 dest = {0};
                        dest.sin6_family = AF_INET6;
                        dest.sin6_port = htons(PORT_ENCHERE);
                        inet_pton(AF_INET6, encheres[enchere_active].group, &dest.sin6_addr);
                        dest.sin6_scope_id = global_iface_index;
                        
                        sendto(sock, relay_msg, sizeof(relay_msg), 0,
                               (struct sockaddr *)&dest, sizeof(dest));
                        
                        printf("[Superviseur] Relais de l'offre de pair %u\n", id);
                    }*/
                    break;
                }
                
                case 10: { // Relayed bid message
                    uint16_t id = ntohs(*(uint16_t*)&buffer[1]);
                    uint32_t numv = ntohl(*(uint32_t*)&buffer[3]);
                    uint32_t prix = ntohl(*(uint32_t*)&buffer[7]);
                    
                    printf("[Enchère] Offre validée de pair %u: NUMV=%u, PRIX=%u\n", 
                           id, numv, prix);
                    break;
                }
                
                default:
                    // Handle text messages
                    buffer[len] = '\0'; // Assure la terminaison
                    printf("[Enchère] %s", buffer);
                    fflush(stdout);
                    break;
            }
        }
    }
    return NULL;
}

// -------------------- Test pour la diffusion des adresses Persos --------------------
// Envoie l'adresse perso à un pair P en TCP unicast
void envoyer_adressePerso_TCP(const char *ip_dest, int port_dest, const char *adressePerso)
{
    int sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("socket TCP");
        return;
    }

    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    inet_pton(AF_INET6, ip_dest, &dest.sin6_addr);
    dest.sin6_port = htons(port_dest);

    if (connect(sock, (struct sockaddr *)&dest, sizeof(dest)) < 0)
    {
        perror("connect TCP");
        close(sock);
        return;
    }

    send(sock, adressePerso, strlen(adressePerso), 0);
    close(sock);
}

// Écoute sur le port TCP donné et reçoit les adressesPerso pendant un timeout
void recevoir_adressesPerso_TCP(int port_tcp, int timeout_sec)
{
    int sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("socket TCP");
        return;
    }

    struct sockaddr_in6 addr = {0};
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(port_tcp);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind TCP");
        close(sock);
        return;
    }

    listen(sock, 5);

    fd_set fds;
    struct timeval timeout = {.tv_sec = timeout_sec, .tv_usec = 0};

    printf("En attente de réponses TCP pendant %ds...\n", timeout_sec);

    while (1)
    {
        FD_ZERO(&fds);
        FD_SET(sock, &fds);

        int ready = select(sock + 1, &fds, NULL, NULL, &timeout);
        if (ready < 0)
        {
            perror("select");
            break;
        }
        else if (ready == 0)
        {
            printf("Timeout atteint, fin d'écoute TCP.\n");
            break;
        }
        else
        {
            int client_sock = accept(sock, NULL, NULL);
            if (client_sock >= 0)
            {
                char buffer[256];
                int len = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
                if (len > 0)
                {
                    buffer[len] = '\0';
                    printf("Reçu adressePerso : %s\n", buffer);
                }
                close(client_sock);
            }
        }
    }

    close(sock);
}

void faire_offre(uint32_t prix)
{
    if (enchere_active < 0) {
        printf("Vous n'êtes pas dans une enchère active.\n");
        return;
    }

    // Create bid message (code 9)
    uint8_t msg[1 + 2 + 4 + 4]; // CODE + ID + NUMV + PRIX
    msg[0] = 9; // CODE = 9 for bid
    uint16_t peer_id = (uint16_t)id_peer;
    uint32_t numv = cpt; // Current auction number

    // Convert to network byte order
    uint16_t id_net = htons(peer_id);
    uint32_t numv_net = htonl(numv);
    uint32_t prix_net = htonl(prix);

    // Copy values to message
    memcpy(&msg[1], &id_net, 2);
    memcpy(&msg[3], &numv_net, 4);
    memcpy(&msg[7], &prix_net, 4);

    // Send the bid message to the auction group
    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    // dest.sin6_port = htons(PORT_ENCHERE);
    // inet_pton(AF_INET6, encheres[enchere_active].group, &dest.sin6_addr);
    dest.sin6_scope_id = global_iface_index;
    dest.sin6_addr = encheres[enchere_active].group;

    sendto(encheres[enchere_active].sock, msg, sizeof(msg), 0,
           (struct sockaddr *)&dest, sizeof(dest));

    printf("Offre envoyée : PRIX=%u\n", prix);
}
