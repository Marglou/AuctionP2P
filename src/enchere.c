// enchere.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <net/if.h>

#include "../include/enchere.h"
#include "../include/superviseur.h"
#include "../include/peer.h"
#include "../include/message.h"
#include "../include/connexion.h"
#include "../include/utils.h"
#include "../include/securite.h"

void afficher_enncheres() {
    printf("Liste des enchères auxquels on participe :\n");
    for (int i = 0; i < p.nb_encheres; i++) {
        printf("Enchère %d : ID=%d, Port=%u\n", i, p.encheres[i].id_enchere, p.encheres[i].port_enchere);
    }
}

int join_enchere(int id, char *group, uint16_t port) {
    if (p.nb_encheres >= MAX_ENCHERES) {
        fprintf(stderr, "Nombre maximum d'enchères atteint.\n");
        return -1;
    }

    for (int i = 0; i < p.nb_encheres; i++) {
        if (p.encheres[i].id_enchere == id) {
            fprintf(stderr, "Vous êtes déjà dans l'enchère %d.\n", id);
            return -1;
        }
    }

    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket enchere");
        return -1;
    }

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));

    struct sockaddr_in6 addr = {0};
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(port);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind enchere");
        close(sock);
        return -1;
    }

    // Abonnement au groupe multicast
    struct ipv6_mreq mreq = {0};
    
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
    mreq.ipv6mr_interface = p.global_iface_index;

    printf("Debug - Joining multicast group %s on interface (index %d)\n", 
           addr_str, p.global_iface_index);

    if (setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) < 0) {
        perror("setsockopt (join group enchere)");
        close(sock);
        return -1;
    }

    // Sauvegarde dans le tableau
    p.encheres[p.nb_encheres].id_enchere = id;
    p.encheres[p.nb_encheres].port_enchere = port;
    p.encheres[p.nb_encheres].sock = sock;
    memcpy(&p.encheres[p.nb_encheres].group, &mreq.ipv6mr_multiaddr, sizeof(struct in6_addr));

    p.enchere_active = p.nb_encheres;

    int *sock_ptr = malloc(sizeof(int));
    if (!sock_ptr)
    {
        perror("malloc");
        close(sock);
        return -1;
    }
    *sock_ptr = sock;

    if (pthread_create(&p.encheres[p.enchere_active].thread_id, NULL, auction_receiver, sock_ptr) != 0)
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
    if (IN6_IS_ADDR_LINKLOCAL(&group_addr.sin6_addr)) {
        group_addr.sin6_scope_id = p.global_iface_index;
    }
    group_addr.sin6_scope_id = p.global_iface_index;
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

    struct in6_addr adresse_perso;
    if (get_adresse_perso_from_socket(p.socket_tcp, &adresse_perso) != 0) {
        fprintf(stderr, "Erreur lors de la récupération de l'adresse personnelle.\n");
        return -1;
    }

    // Exemple de clé publique (remplacez par la clé réelle)
    unsigned char cle[113] = {0};

    // s'ajouter à la liste des enchères
    if (add_peer(&p.encheres[p.nb_encheres].liste_participants, p.id_peer, adresse_perso, p.port_perso, cle) != 0) {
        fprintf(stderr, "Erreur lors de l'ajout de l'utilisateur en tant que peer.\n");
        return -1;
    }
    p.encheres[p.nb_encheres].nb_pairs += 1; 
    p.nb_encheres++;
    return 0;
}


void creer_enchere()
{
    if (p.nb_encheres >= MAX_ENCHERES) {
        fprintf(stderr, "Le nombre maximum d'enchères a été atteint.\n");
        return;
    }

    if (is_superviseur == 1) {
        printf("Deja superviseur d'une enchere\n");
        return;
    }

    char auction_group[INET6_ADDRSTRLEN];

    int auction_num_id = p.id_peer * 100 + (p.cpt + 1);
    // Generate a random multicast address in the ff15::/16 range
    int r = rand() & 0xFFFF; // max 4 chiffres hexadécimaux
    snprintf(auction_group, sizeof(auction_group), "ff12::%04x", r); // Ensure 4 hex digits with leading zeros

    // Debug print the generated multicast address
    printf("Debug - Generated multicast address: %s\n", auction_group);

    p.enchere_active++;
    p.encheres[p.enchere_active].id_enchere = auction_num_id;
    
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
    memcpy(&p.encheres[p.enchere_active].group, &group_addr, sizeof(struct in6_addr));

    // Generate a random port for the auction
    uint16_t port_enchere = generate_random_port();
    p.encheres[p.enchere_active].port_enchere = port_enchere;

    // Create and send message 8 (auction initiation)
    // uint8_t msg[1 + 2 + 4 + 4]; // CODE + ID + NUMV + PRIX
    // msg[0] = 200; // CODE = 8 for auction initiation
    // uint16_t peer_id = auction_num_id;

    // Join the auction group first
    if (join_enchere(auction_num_id, auction_group, port_enchere) != 0) {
        fprintf(stderr, "Erreur lors de la création de l'enchère.\n");
        return;
    }

    // Send the message to the auction group
    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(p.encheres[p.enchere_active].port_enchere);
    memcpy(&dest.sin6_addr, &p.encheres[p.enchere_active].group, sizeof(struct in6_addr));
    dest.sin6_scope_id = p.global_iface_index;

    // sendto(p.encheres[p.enchere_active].sock, msg, sizeof(msg), 0,
    //        (struct sockaddr *)&dest, sizeof(dest));

    char ip_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &p.encheres[p.enchere_active].group, ip_str, sizeof(ip_str));
    printf("Enchère initiée : ID=%d, ADR=%s\n", auction_num_id, ip_str);

    enchere_supervise = auction_num_id;
    is_superviseur = 1; // Initialiser le nombre de pairs à 1 (le superviseur)
}

// ----------------------------------------------------------------------------

int msg_join_enchere()
{
    const int timeout_sec = 3;
    const int max_attempts = 3;

    int attempts = 0;
    time_t start = time(NULL);

    printf("Tentative de rejoindre une enchère...  %d\n", p.listener_tcp.response_received);
   //while (attempts++ < max_attempts && p.listener_tcp.response_received == 0) {
   // AJOUTER MUTEX OU AUTRE CHOSE A VOIR 
        printf("Reponse recue %d\n", p.listener_tcp.response_received);
        printf("Tentative %d : envoi du message CODE 3.\n", attempts);
        char msg[3] = {3};
        // uint16_t port_p = htons(p.port_perso);
        // memcpy(&msg[1], &port_p, 2);

        if (send_multicast(p.socket_udp, msg, sizeof(msg)) != 0) {
            fprintf(stderr, "Erreur lors de l'envoi du message de demande de jointure.\n");
            return -1;
        }
        sleep(1);
    //}

    return 0;
}

// // Thread pour recevoir les messages du groupe d'enchères
// void *auction_receiver(void *arg)
// {
//     int sock = *(int *)arg;
//     free(arg); // Libère la mémoire allouée dynamiquement

//     char buffer[BUF_SIZE];
//     struct sockaddr_in6 src;
//     socklen_t srclen = sizeof(src);

//     while (1)
//     {
//         memset(buffer, 0, BUF_SIZE);
//         ssize_t len = recvfrom(sock, buffer, BUF_SIZE - 1, 0,
//                                (struct sockaddr *)&src, &srclen);

//         if (len > 0)
//         {
//             buffer[len] = '\0';
            
//             // Handle binary messages with codes
//             uint8_t code = (uint8_t)buffer[0];

//             if (code == 10){
//                 printf("[ENCHERE] : message 10 recu : debut consensus \n");
                
//                 uint8_t consensus_msg[1024];
//                 char *message = "Je valide la vente";
//                 unsigned char *signature = NULL;
//                 size_t siglen = 0;

//                 // Signature du message
//                 if (!sign(p.ed_privkey, (unsigned char*)message, &signature, &siglen)) {
//                     fprintf(stderr, "Erreur lors de la signature\n");
//                     return -1;
//                 }

//                 int len = msg_1(consensus_msg, p.id_peer, message, signature, siglen);
//                 if (len > 0) {
//                     sendto(p.socket_udp, consensus_msg, sizeof(consensus_msg), 0,
//                            (struct sockaddr *)&src, srclen);   
//                     printf("Message de consensus envoyé : %s\n", message); 
//                 } 

//             } else if (code == 2 && p.encheres[p.enchere_active].is_superviseur == 0)  {
//                 //p.encheres[p.enchere_active].is_superviseur == 0
//                 printf("Message 2 reçu : début du consensus\n");
//                 struct message_2 parsed_msg = {0};
//                 printf("retour:%d",parse_msg_2(buffer, len, &parsed_msg));
//                 if (parse_msg_2(buffer, len, &parsed_msg) == 0) {
//                     printf("Message 2 reçu : ID=%d, Message=%s\n NB=%d\n", parsed_msg.id, parsed_msg.mess, parsed_msg.nb_validations);
//                     if (parsed_msg.nb_validations == p.encheres[p.enchere_active].nb_pairs - 1) {
//                         printf("Consensus atteint pour le message 2.\n");
//                         // RECUPERE LES SIGNATURE ET VERIFIER BLABLABLABL
//                     }
//                 }
//             } else if (code == 8 || code == 9 || code == 14 || code == 15) {
//                 struct message_8 msg;
//                 if (parse_msg_8_9_10(buffer, len, &msg) == 0) {
//                     handle_auction_message(code, msg.id, msg.numv, msg.prix);
//                 }
//             } else if (code == 11) {
//                 FinalizationWarningMessage msg;
//                 if (parse_msg_11(buffer, len, &msg) == 0) {
//                     handle_auction_message(code, msg.id, msg.numv, msg.prix);
//                 }
//             } else if (code == 12) {
//                 FinalizationMessage msg;
//                 if (parse_msg_12(buffer, len, &msg) == 0) {
//                     handle_auction_message(code, msg.id, msg.numv, msg.prix);
//                 }
//             } else {
//                 // Handle text messages 
//                 buffer[len] = '\0'; // Assure la terminaison
//                 printf("[Enchère] %s\n", buffer);
//                 fflush(stdout);                
//             }
//         } else if (len < 0) {
//             perror("recvfrom");
//             break;
//         } else {
//             printf("Aucun message reçu.\n");
//             check_auction_timeout();
//         }
//     }
//     return NULL;
// }

// Thread pour recevoir les messages du groupe d'enchères
void *auction_receiver(void *arg)
{
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

    int sock = *(int *)arg;
    free(arg); // Libère la mémoire allouée dynamiquement

    char buffer[BUF_SIZE];
    struct sockaddr_in6 src;
    socklen_t srclen = sizeof(src);

    while (stop_threads == 0)
    {
        memset(buffer, 0, BUF_SIZE);

        // Préparer select()
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);

        struct timeval timeout;
        timeout.tv_sec = 5;   // 5 secondes d'attente maximum
        timeout.tv_usec = 0;

        int ready = select(sock + 1, &readfds, NULL, NULL, &timeout);

        if (ready < 0)
        {
            perror("select");
            break;
        }
        else if (ready == 0  && p.encheres[p.enchere_active].is_superviseur == 1 && p.encheres[p.enchere_active].numv != 0)
        {
            // Aucun message reçu pendant 5 secondes
            printf("Aucun message reçu depuis 5 secondes\n");
            check_auction_timeout(); // Traitement de timeout
            continue;
        }

        ssize_t len = recvfrom(sock, buffer, BUF_SIZE - 1, 0,
                               (struct sockaddr *)&src, &srclen);

        if (len > 0)
        {
            
            buffer[len] = '\0';
            uint8_t code = (uint8_t)buffer[0];

            if (code == 10)
            {
                printf("[ENCHERE] : message 10 recu : debut consensus\n");

                uint8_t consensus_msg[1024];
                char *message = "Je valide la vente";
                unsigned char *signature = NULL;
                size_t siglen = 0;

                if (!sign(p.ed_privkey, (unsigned char *)message, &signature, &siglen))
                {
                    fprintf(stderr, "Erreur lors de la signature\n");
                    return NULL;
                }

                int len_msg = msg_1(consensus_msg, p.id_peer, message, signature, siglen);
                if (len_msg > 0)
                {
                    sendto(p.socket_udp, consensus_msg, len_msg, 0,
                           (struct sockaddr *)&src, srclen);
                    printf("Message de consensus envoyé : %s\n", message);
                }

            }
            else if (code == 2 && p.encheres[p.enchere_active].is_superviseur == 0)
            {
                printf("Message 2 reçu : début du consensus\n");
                struct message_2 parsed_msg = {0};

                if (parse_msg_2(buffer, len, &parsed_msg) == 0)
                {
                    printf("Message 2 reçu : ID=%d, Message=%s\n NB=%d\n",
                           parsed_msg.id, parsed_msg.mess, parsed_msg.nb_validations);

                    if (parsed_msg.nb_validations == p.encheres[p.enchere_active].nb_pairs - 1)
                    {
                        printf("Consensus atteint pour le message 2.\n");
                        // Vérification des signatures ici si nécessaire
                    }
                }
            }
            else if (code == 8 || code == 9 || code == 14 || code == 15)
            {
                struct message_8 msg;
                if (parse_msg_8_9_10(buffer, len, &msg) == 0)
                {
                    printf("Message %d reçu : ID=%d, NUMV=%u, PRIX=%u\n", code, msg.id, msg.numv, msg.prix);
                    handle_auction_message(code, msg.id, msg.numv, msg.prix);
                }
            }
            else if (code == 11)
            {
                FinalizationWarningMessage msg;
                if (parse_msg_11(buffer, len, &msg) == 0)
                {
                    handle_auction_message(code, msg.id, msg.numv, msg.prix);
                }
            }
            else if (code == 12)
            {
                FinalizationMessage msg;
                if (parse_msg_12(buffer, len, &msg) == 0)
                {
                    handle_auction_message(code, msg.id, msg.numv, msg.prix);
                }
            }
            else
            {
                // Message texte brut
                printf("[Enchère] %s\n", buffer);
                fflush(stdout);
            }
        }
        else if (len < 0)
        {
            perror("recvfrom");
            break;
        }
    }

    pthread_exit(NULL);
    return NULL;
}


// ---------------------------------- INITIER VENTE -------------------------------------------
// COMMENT ON SAIT DANS QUELLE ENCHERE ON EST ?
int init_vente () {
    if (p.enchere_active < 0) {
        printf("Vous n'avez pas d'enchère active.\n");
        return -1;
    }
    p.cpt++;
    char auction_num_id_str[16];
    snprintf(auction_num_id_str, sizeof(auction_num_id_str), "%d%d", p.id_peer, p.cpt + 1);
    int numv = atoi(auction_num_id_str);    
    uint32_t initial_price = 0;
    int essais = 0;
    const int max_essais = 5;
    while (essais < max_essais) {
        printf("Entrez le prix de départ de l'enchère : ");
        if (scanf("%u", &initial_price) == 1) {
            break;
        } else {
            fprintf(stderr, "Erreur : entrée invalide pour le prix.\n");
            // Vider le buffer d'entrée
            int c;
            while ((c = getchar()) != '\n' && c != EOF);
            essais++;
        }
    }
    if (essais == max_essais) {
        printf("Trop d'essais invalides, la vente sera créée avec un prix de départ à 0.\n");
        initial_price = 0;
    }
    char msg[1 + 2 + 4 + 4]; // CODE + ID + NUMV + PRIX
    if(msg_8_9_10(msg, 8,p.id_peer, numv, initial_price) != 11) {
        printf("Erreur message 8");
    }

    // Send the message to the auction group
    if (send_msg_enchere(msg, sizeof(msg), p.enchere_active, p.encheres[p.enchere_active].sock) != 0) {
        fprintf(stderr, "Erreur lors de l'envoi du message d'initiation de vente.\n");
        return -1;
    }

    char ip_str[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, &p.encheres[p.enchere_active].group, ip_str, sizeof(ip_str)) == NULL) {
        perror("inet_ntop");
        return -1;
    }

    printf("Enchère initiée : ID=%d, ADR=%s\n", numv, ip_str);
    is_superviseur = 1;
    enchere_supervise = p.enchere_active;
    p.encheres[p.enchere_active].numv = numv;
    init_auction_supervisor(numv, initial_price);
}

int sur_enchere() {
    if (p.enchere_active < 0) {
        printf("Vous n'avez pas d'enchère active.\n");
        return -1;
    }
    uint32_t prix = 0;
    int essais = 0;
    const int max_essais = 5;
    while (essais < max_essais) {
        printf("Entrez la surenchere : ");
        if (scanf("%u", &prix) == 1) {
            break;
        } else {
            fprintf(stderr, "Erreur : entrée invalide pour le prix.\n");
            // Vider le buffer d'entrée
            int c;
            while ((c = getchar()) != '\n' && c != EOF);
            essais++;
        }
    }
    if (essais == max_essais) {
        printf("Trop d'essais invalides, la vente sera créée avec un prix de départ à 0.\n");
        prix = 0;
    }

    faire_offre(prix);
    return 0;
}


void faire_offre(uint32_t prix)
{
    if (p.enchere_active < 0) {
        printf("Vous n'êtes pas dans une enchère active.\n");
        return;
    }

    // Create bid message (code 9)
    uint8_t msg[1 + 2 + 4 + 4]; // CODE + ID + NUMV + PRIX
    msg[0] = 9; // CODE = 9 for bid
    uint16_t peer_id = (uint16_t)p.id_peer;
    uint32_t numv = p.encheres[p.enchere_active].numv; // Current auction number

    // Convert to network byte order
    uint16_t id_net = htons(peer_id);
    uint32_t numv_net = htonl(numv);
    uint32_t prix_net = htonl(prix);

    // Copy values to message
    memcpy(&msg[1], &id_net, 2);
    memcpy(&msg[3], &numv_net, 4);
    memcpy(&msg[7], &prix_net, 4);

    // Send the bid message to the auction group
    if (send_msg_enchere(msg, sizeof(msg), p.enchere_active, p.encheres[p.enchere_active].sock) != 0) {
        fprintf(stderr, "Erreur lors de l'envoi de l'offre.\n");
        return;
    }
    printf("Offre envoyée : PRIX=%u\n", prix);
}

int send_msg_enchere(uint8_t *msg, size_t len, int num_enchere, int sock)
{
    if (p.enchere_active < 0) {
        fprintf(stderr, "Erreur : pas d'enchère active.\n");
        return -1;
    }

    if (num_enchere < 0 || num_enchere >= p.nb_encheres) {
        num_enchere = p.enchere_active; // Utiliser l'enchère active par défaut
    }

    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(p.encheres[num_enchere].port_enchere);
    memcpy(&dest.sin6_addr, &p.encheres[num_enchere].group, sizeof(struct in6_addr));
    if (IN6_IS_ADDR_LINKLOCAL(&dest.sin6_addr)) {
        dest.sin6_scope_id = p.global_iface_index;
    }
    dest.sin6_scope_id = p.global_iface_index;
    ssize_t sent_bytes = sendto(sock, msg, len, 0,
                                 (struct sockaddr *)&dest, sizeof(dest));

    if (sent_bytes < 0) {
        perror("sendto");
        return -1;
    }

    return 0;
}