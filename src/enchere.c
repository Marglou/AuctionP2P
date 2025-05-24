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
#include "../include/udp_response.h"

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

    printf("Debug - Joining multicast group %s on interface (index %d)\n", addr_str, p.global_iface_index);

    if (setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) < 0) {
        perror("setsockopt (join group enchere)");
        close(sock);
        return -1;
    }

    printf("nb enchere : %d\n", p.nb_encheres);
    printf("enchere active : %d\n", p.enchere_active);
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
    // if (IN6_IS_ADDR_LINKLOCAL(&group_addr.sin6_addr)) {
    //     group_addr.sin6_scope_id = p.global_iface_index;
    // }
    p.global_iface_index = get_active_interface();
    group_addr.sin6_scope_id = p.global_iface_index;
    // Message d'acceptation
    char accept_msg[BUF_SIZE];
    snprintf(accept_msg, sizeof(accept_msg), "[ACCEPTED] Vous avez rejoint l'enchère %d\n", id);
    
    printf("scoe ip %d\n", p.global_iface_index);
    char ipbuf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &group_addr.sin6_addr, ipbuf, sizeof(ipbuf));
    printf("sendto debug: ip=%s port=%d scope_id=%d family=%d\n",
           ipbuf, ntohs(group_addr.sin6_port), group_addr.sin6_scope_id, group_addr.sin6_family);
    if (sendto(sock, accept_msg, strlen(accept_msg), 0, (struct sockaddr *)&group_addr, sizeof(group_addr)) < 0)
    {
        perror("sendto (accept message)");
        printf("errno : %d\n", errno);
        close(sock);
        return -1;
    }

    memcpy(&p.encheres[p.nb_encheres].group, &mreq.ipv6mr_multiaddr, sizeof(struct in6_addr));
    char addr_sr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &p.encheres[p.enchere_active].group, addr_sr, sizeof(addr_sr));
    printf("Debug - Multicast group address: %s\n", addr_sr);

    

    printf("Vous avez rejoint l'enchère %d sur %s\n", id, addr_str);

    struct in6_addr adresse_perso = {0};
    if (p.socket_tcp != 0) {

        // printf("socket_tcp != 0\n");
        if (get_adresse_perso_from_socket(p.socket_tcp, &adresse_perso) != 0) {
            fprintf(stderr, "Erreur lors de la récupération de l'adresse personnelle.\n");
            return -1;
        }
    }


    // Exemple de clé publique (remplacez par la clé réelle)
    unsigned char cle[113] = {0};

    if (adresse_perso.s6_addr[0] == 0) {
        adresse_perso = p.adr_perso.sin6_addr;
    }

    // s'ajouter à la liste des enchères
    if (add_peer(&p.encheres[p.enchere_active].liste_participants, p.id_peer, adresse_perso, p.port_perso, cle) != 0) {
        fprintf(stderr, "Erreur lors de l'ajout de l'utilisateur en tant que peer.\n");
        return -1;
    }


    p.encheres[p.enchere_active].nb_pairs += 1; 
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
    // printf("Debug - Generated multicast address: %s\n", auction_group);

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
char debug_addr[INET6_ADDRSTRLEN];
inet_ntop(AF_INET6, &p.encheres[p.enchere_active].group, debug_addr, sizeof(debug_addr));
printf("[DEBUG] Adresse multicast stockée : %s\n", debug_addr);

    // Generate a random port for the auction
    uint16_t port_enchere = generate_random_port();
    p.encheres[p.enchere_active].port_enchere = port_enchere;

    enchere_supervise = auction_num_id;
    is_superviseur = 1; //(le superviseur)
    
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

}

// ----------------------------------------------------------------------------

int msg_join_enchere()
{
    // const int timeout_sec = 3;
    // const int max_attempts = 3;

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
        // sleep(1);
    //}

    return 0;
}

void *gestion_disp_superviseur(void *arg)
{
    printf("Thread de supervision lancé\n");
    pthread_mutex_lock(&p.encheres[p.enchere_active].superviseur_mutex);
    while (p.encheres[p.enchere_active].superviseur_actif) {
        pthread_cond_wait(&p.encheres[p.enchere_active].superviseur_cond, &p.encheres[p.enchere_active].superviseur_mutex);
        // Réveillé quand superviseur_actif peut avoir changé
    }
    pthread_mutex_unlock(&p.encheres[p.enchere_active].superviseur_mutex);
    printf("Thread de supervision arrêté\n");
    pthread_exit(NULL);
}


// Thread pour recevoir les messages du groupe d'enchères
void *auction_receiver(void *arg)
{
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

    int sock = *(int *)arg;
    free(arg); // Libère la mémoire allouée dynamiquement

    uint8_t buffer[BUF_SIZE];
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
        timeout.tv_sec = 3;   // 5 secondes d'attente maximum
        timeout.tv_usec = 0;

        int ready = select(sock + 1, &readfds, NULL, NULL, &timeout);

        if (ready < 0)
        {
            perror("select");
            break;
        }
        else if (ready == 0  && p.encheres[p.enchere_active].is_superviseur == 1 && p.encheres[p.enchere_active].numv != 0 && p.encheres[p.enchere_active].consensus == 0)
        {
            //ajouter consensus && p.encheres[p.enchere_active].consensus == 0
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

            if (code == 10 && p.encheres[p.enchere_active].is_superviseur == 0)
            {
                printf("[ENCHERE] : message 10 recu : debut consensus\n");

                uint8_t consensus_msg[1024];
                char *message = "Je valide la vente";
                unsigned char *signature = NULL;
                size_t siglen = 0;
                p.encheres[p.enchere_active].consensus=1;

                if (!sign(p.ed_privkey, (unsigned char *)message, &signature, &siglen))
                {
                    fprintf(stderr, "Erreur lors de la signature\n");
                    p.encheres[p.enchere_active].consensus=0;
                    return NULL;
                }

                int len_msg = msg_1(consensus_msg, p.id_peer, message, signature, siglen); // Attention
                if (len_msg > 0)
                {
                    // Track the UDP message before sending
                    /*if (track_udp_message(&p.udp_responses, 1, p.id_peer, consensus_msg, len_msg) != 0) {
                        fprintf(stderr, "Failed to track UDP message 1\n");
                    }*/
                    
                    sendto(p.socket_udp, consensus_msg, len_msg, 0,
                           (struct sockaddr *)&src, srclen);
                    printf("Message de consensus envoyé : %s\n", message);
                }

            }
            else if (code == 2 )
            {
                printf("Message 2 reçu : début du consensus\n");
                struct message_2 parsed_msg = {0};

                if (parse_msg_2(buffer, len, &parsed_msg) == 0)
                {
                    printf("Message 2 reçu : ID=%d, Message=%s\n NB=%d\n",
                           parsed_msg.id, parsed_msg.mess, parsed_msg.nb_validations);
                    if(parsed_msg.id != p.encheres[p.enchere_active].my_id){
                        if (parsed_msg.nb_validations == p.encheres[p.enchere_active].nb_pairs - 1)
                        {
                            printf("Consensus atteint pour le message 2.\n");
                            p.encheres[p.enchere_active].consensus = 0;
                            // Vérification des signatures ici si nécessaire
                        }
                        if (strcmp(parsed_msg.mess,"superviseur")==0){
                            printf("Message Nouveau SUperviseur\n");
                            p.encheres[p.enchere_active].is_superviseur = 1;
                            pthread_mutex_lock(&p.encheres[p.enchere_active].superviseur_mutex);
                            p.encheres[p.enchere_active].superviseur_actif = 0;
                            pthread_cond_signal(&p.encheres[p.enchere_active].superviseur_cond);  // Réveille le thread en attente
                            pthread_mutex_unlock(&p.encheres[p.enchere_active].superviseur_mutex);
                            return 0;
                        }
                        if (strcmp(parsed_msg.mess,"quitter")==0){
                        
                            int n = supp_peer_list(&p.encheres[p.enchere_active].liste_participants,parsed_msg.id);
                            if (n==0){
                                printf("suppresion du peer\n");
                            }
                            printf("avant: %d\n",p.encheres[p.enchere_active].nb_pairs);
                            p.encheres[p.enchere_active].nb_pairs--;
                            printf("apres: %d\n",p.encheres[p.enchere_active].nb_pairs);
                        }
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
            }else if (code == 13)
            {
                struct message_13 msg;
                if(parse_msg_13(buffer,len,&msg)==0){
                    printf("ID msg %d, my id %d\n", msg.id , p.encheres[p.enchere_active].my_id);
                    //if(msg.id != p.encheres[p.enchere_active].my_id){
                    if(src.sin6_port != htons(p.port_perso)){
                        printf("[ENCHERE] : message 13 recu : debut consensus\n");

                        uint8_t consensus_msg[1024];
                        char *message = "quitter";
                        unsigned char *signature = NULL;
                        size_t siglen = 0;

                        if (!sign(p.ed_privkey, (unsigned char *)message, &signature, &siglen))
                        {
                            fprintf(stderr, "Erreur lors de la signature\n");
                            return NULL;
                        }

                        int len_msg = msg_1(consensus_msg, msg.id, message, signature, siglen);
                        if (len_msg > 0)
                        {
                            sendto(p.socket_udp, consensus_msg, len_msg, 0,
                                (struct sockaddr *)&src, srclen);
                            printf("Message de consensus 13 envoyé : %s\n", message);
                        }
                        
                    }
                }
                
            }
            else if (code == 16 ) {
                if (p.encheres[p.enchere_active].is_superviseur == 1) {
                    stop_threads = 1;
                    break;
                }
                struct message_16_17 msg;
                if (parse_msg_16_17(buffer, len, &msg) == 0) {
                    printf("\n\nMessage 16 reçu : ID=%d, NUMV=%u,\n", msg.id, msg.numv);
                    if (supp_peer_list(&p.encheres[p.enchere_active].liste_participants, msg.id) == 0) {
                        printf("Peer %d supprimé de la liste des participants.\n", msg.id);
                        p.encheres[p.enchere_active].nb_pairs--;

                        if (p.encheres[p.enchere_active].nb_pairs == 1){
                            printf("Seul au monde, je suis superviseur\n");
                            p.encheres[p.enchere_active].is_superviseur = 1;
                            return 0;
                        }

                        if (p.encheres[p.enchere_active].is_superviseur == 0){                        
                            // MSG 30 pour enclencher le consensus
                            uint8_t consensus_msg[1024];
                            char *message = "superviseur";
                            if (msg_30(consensus_msg, p.encheres[p.enchere_active].numv, message) < 0) {
                                fprintf(stderr, "Erreur lors de la construction du message 30.\n");
                                return NULL;
                            }
                            // Envoi du message 30
                            send_msg_enchere(consensus_msg, sizeof(consensus_msg), p.enchere_active, p.socket_udp);
                            printf("Message de consensus 30 envoyé : %s\n", message);

                            // lancer thread consensus 
                            p.encheres[p.enchere_active].superviseur_actif = 1;
                            pthread_mutex_init(&p.encheres[p.enchere_active].superviseur_mutex, NULL);
                            pthread_cond_init(&p.encheres[p.enchere_active].superviseur_cond, NULL);
                            pthread_create(&p.encheres[p.enchere_active].tid_consensus, NULL, gestion_disp_superviseur, NULL);
                        }

                    } else {
                        printf("Erreur lors de la suppression du peer %d de la liste des participants.\n", msg.id);
                    }
                }
            }
            else if (code == 30) {
                struct message_30 msg;
                if (parse_msg_30(buffer, len, &msg) == 0) {
                    printf("Message 30 reçu : NUMV=%u Mess=%s\n", msg.numv, msg.mess);
                    uint8_t consensus_msg[1024];
                    unsigned char *signature = NULL;
                    size_t siglen = 0;
                    if (!sign(p.ed_privkey, (unsigned char *)msg.mess, &signature, &siglen))
                    {
                        fprintf(stderr, "Erreur lors de la signature\n");
                        return NULL;
                    }

                    int len_msg = msg_1(consensus_msg, p.encheres[p.enchere_active].my_id, msg.mess, signature, siglen);
                    if (len_msg > 0)
                    {
                        sendto(p.socket_udp, consensus_msg, len_msg, 0,
                            (struct sockaddr *)&src, srclen);
                        printf("Message de consensus superviseur envoyé : %s\n", msg.mess);
                    }
                    // Handle the message as needed
                }
            }
            else if (code == 17) {
                struct message_16_17 msg;
                if (parse_msg_16_17(buffer, len, &msg) == 0) {
                    printf("Message 17 reçu : ID=%d, NUMV=%u\n", msg.id, msg.numv);
                    printf("superviseur %d\n", p.encheres[p.enchere_active].superviseur_actif);
                    // Handle the message as needed
                }

            }
            else if (code == 51){
                struct message_51 msg;
                if (parse_msg_51(buffer, len, &msg) == 0){
                    if (supp_peer_list(&p.encheres[p.enchere_active].liste_participants, msg.id) == 0){
                        p.encheres[p.enchere_active].nb_pairs--;
                        printf("Peer id  supprimer: %d\n", msg.id);
                    }
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
    if(msg_8_9_10((uint8_t *) msg, 8,p.id_peer, numv, initial_price) != 11) {
        printf("Erreur message 8");
    }

    // Send the message to the auction group
    if (send_msg_enchere((uint8_t *)msg, sizeof(msg), p.enchere_active, p.encheres[p.enchere_active].sock) != 0) {
        fprintf(stderr, "Erreur lors de l'envoi du message d'initiation de vente.\n");
        return -1;
    }

    char ip_str[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, &p.encheres[p.enchere_active].group, ip_str, sizeof(ip_str)) == NULL) {
        perror("inet_ntop");
        return -1;
    }

    printf("Vente initiée : ID=%d, ADR=%s\n", numv, ip_str);
    is_superviseur = 1;
    enchere_supervise = p.enchere_active;
    p.encheres[p.enchere_active].numv = numv;
    init_auction_supervisor(numv, initial_price);
    p.encheres[p.enchere_active].is_superviseur = 1;
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

void mettre_fin()
{
    if (p.enchere_active < 0) {
        printf("Vous n'êtes pas dans une enchère active.\n");
        return;
    }
    uint8_t msg[1 + 2]; // CODE + ID 
    msg[0] = 13; 
    uint16_t peer_id = (uint16_t)p.encheres[p.enchere_active].my_id;
    uint16_t id_net = htons(peer_id);
    // Copy values to message
    memcpy(&msg[1], &id_net, 2);

    // Send the bid message to the auction group
    if (send_msg_enchere(msg, sizeof(msg), p.enchere_active, p.socket_udp) != 0) {
        fprintf(stderr, "Erreur lors de l'envoi pour quitter.\n");
        return;
    }
    printf("En cours pour partir\n");
    
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

int clean_encheres(int id_enchere) {
    // Quitter toutes les enchères (groupes multicast) et fermer les sockets
    for (int i = 0; i < p.nb_encheres; i++) {
        if (p.encheres[i].id_enchere == id_enchere){
            if (p.encheres[i].sock >= 0) {
                stop_threads = 1; // Attention 
                struct ipv6_mreq mreq;
                memset(&mreq, 0, sizeof(mreq));
                memcpy(&mreq.ipv6mr_multiaddr, &p.encheres[i].group, sizeof(struct in6_addr));
                mreq.ipv6mr_interface = p.global_iface_index;

                // Se désabonner proprement du groupe multicast
                if (setsockopt(p.encheres[i].sock, IPPROTO_IPV6, IPV6_LEAVE_GROUP, &mreq, sizeof(mreq)) < 0) {
                    perror("setsockopt IPV6_LEAVE_GROUP");
                }

                // Libération de la liste des participants si allouée dynamiquement
                free_peer_list(p.encheres[i].liste_participants);  // à implémenter si nécessaire
                p.encheres[i].liste_participants = NULL;
               // Détruire mutex/cond si utilisés
                pthread_mutex_destroy(&p.encheres[i].superviseur_mutex);
                pthread_cond_destroy(&p.encheres[i].superviseur_cond);

                if (p.encheres[i].thread_id) {
                    pthread_cancel(p.encheres[i].thread_id);
                    pthread_join(p.encheres[i].thread_id, NULL);
                }
                close(p.encheres[i].sock);
                p.encheres[i].sock = -1;

                // Décaler les enchères suivantes dans le tableau
                for (int j = i; j < p.nb_encheres - 1; j++) {
                    p.encheres[j] = p.encheres[j + 1];
                }
                memset(&p.encheres[p.nb_encheres - 1], 0, sizeof(EnchereSocket));

                p.nb_encheres--; // Décrémenter le nombre d'enchères
                stop_threads = 0;
                return 0; // Succès
            }

        }
    }
    return -1; // Pas trouvé
}

// Function to handle peer disappearance
int handle_peer_disappearance(uint16_t *absent_peer_ids, uint16_t num_absent) {
    // Set current peer as supervisor for this consensus
    p.encheres[p.enchere_active].is_superviseur = 1;
    is_superviseur = 1;

    // Create message 18 to signal removal of absent peers
    uint8_t msg_buffer[BUF_SIZE];
    int msg_len = msg_18(msg_buffer, p.id_peer, num_absent, absent_peer_ids);
    if (msg_len < 0) {
        fprintf(stderr, "Error creating message 18\n");
        return -1;
    }

    // Multicast message 18 on the auction address
    if (send_msg_enchere(msg_buffer, msg_len, p.enchere_active, p.encheres[p.enchere_active].sock) < 0) {
        fprintf(stderr, "Error sending message 18\n");
        return -1;
    }

    // Wait for validation messages (code 1) from other peers
    time_t start_time = time(NULL);
    int nb_validations = 0;
    struct valid_peer *head = NULL;
    int retry_count = 0;
    int max_retries = 2; // Total of 3 attempts (initial + 2 retries)
    int expected_validations = p.encheres[p.enchere_active].nb_pairs - num_absent - 1; // -1 for supervisor

    while (nb_validations < expected_validations) {
        // Check timeout for validation collection
        if (time(NULL) - start_time > RESPONSE_TIMEOUT_SEC) {
            if (retry_count < max_retries) {
                // Retry requesting validation from unresponsive peers
                peer_list *peer = p.encheres[p.enchere_active].liste_participants;
                while (peer != NULL) {
                    bool is_absent = false;
                    for (int i = 0; i < num_absent; i++) {
                        if (peer->id == absent_peer_ids[i]) {
                            is_absent = true;
                            break;
                        }
                    }
                    
                    if (!is_absent) {
                        bool has_validated = false;
                        struct valid_peer *cur = head;
                        while (cur != NULL) {
                            if (cur->id == peer->id) {
                                has_validated = true;
                                break;
                            }
                            cur = cur->next;
                        }

                        if (!has_validated) {
                            // Request validation from this peer
                            struct sockaddr_in6 peer_addr = {0};
                            peer_addr.sin6_family = AF_INET6;
                            peer_addr.sin6_port = htons(peer->port_tcp);
                            memcpy(&peer_addr.sin6_addr, &peer->ip, sizeof(struct in6_addr));

                            if (sendto(p.socket_udp, msg_buffer, msg_len, 0,
                                     (struct sockaddr*)&peer_addr,
                                     sizeof(struct sockaddr_in6)) < 0) {
                                perror("Error requesting validation");
                            }
                        }
                    }
                    peer = peer->next;
                }
                retry_count++;
                start_time = time(NULL); // Reset timer for next retry
            } else {
                // Max retries reached, proceed with collected validations
                break;
            }
        }

        // Receive and process validation messages
        uint8_t buffer[BUF_SIZE];
        struct sockaddr_in6 src;
        socklen_t srclen = sizeof(src);
        ssize_t len = recvfrom(p.socket_udp, buffer, sizeof(buffer), 0,
                             (struct sockaddr*)&src, &srclen);

        if (len > 0 && buffer[0] == 1) {
            struct message_1 parsed_msg;
            if (parse_msg_1(buffer, len, &parsed_msg) == 0) {
                // Get peer's public key for signature verification
                char peer_id_str[6];
                snprintf(peer_id_str, sizeof(peer_id_str), "%u", parsed_msg.id);
                EVP_PKEY *peer_pubkey = get_peer_pubkey(peer_id_str);
                if (peer_pubkey) {
                    if (verify_message(peer_pubkey, (unsigned char *)msg_buffer, msg_len, 
                                     parsed_msg.sig, parsed_msg.lsig)) {
                        add_valid_peer(&head, parsed_msg.id, parsed_msg.lsig, parsed_msg.sig);
                        nb_validations++;
                    }
                    EVP_PKEY_free(peer_pubkey);
                }
            }
        }
    }

    // Sign the original message as supervisor
    unsigned char *supervisor_signature = NULL;
    size_t supervisor_siglen = 0;
    if (!sign(p.ed_privkey, msg_buffer, &supervisor_signature, &supervisor_siglen)) {
        fprintf(stderr, "Error signing consensus message\n");
        free_valid_peer_list(head);
        return -1;
    }

    // Create and send final consensus message
    uint8_t final_msg[BUF_SIZE];
    int final_msg_len;

    if (nb_validations <= 3) {
        // Send single CODE=2 message with all validations
        final_msg_len = msg_2(final_msg, p.id_peer, (char *) msg_buffer, supervisor_signature, 
                            supervisor_siglen, nb_validations);
        
        // Append all validations
        size_t offset = final_msg_len;
        struct valid_peer *cur = head;
        while (cur != NULL) {
            uint16_t id_net = htons(cur->id);
            memcpy(final_msg + offset, &id_net, sizeof(uint16_t));
            offset += sizeof(uint16_t);
            final_msg[offset++] = cur->lsig;
            memcpy(final_msg + offset, cur->sig, cur->lsig);
            offset += cur->lsig;
            cur = cur->next;
        }

        if (send_msg_enchere(final_msg, offset, p.enchere_active, 
                           p.encheres[p.enchere_active].sock) < 0) {
            fprintf(stderr, "Error sending final consensus message\n");
            free(supervisor_signature);
            free_valid_peer_list(head);
            return -1;
        }
    } else {
        // Send initial CODE=2 with first 3 validations
        final_msg_len = msg_2(final_msg, p.id_peer, (char *) msg_buffer, supervisor_signature, 
                            supervisor_siglen, 3);
        
        // Append first 3 validations
        size_t offset = final_msg_len;
        struct valid_peer *cur = head;
        for (int i = 0; i < 3 && cur != NULL; i++) {
            uint16_t id_net = htons(cur->id);
            memcpy(final_msg + offset, &id_net, sizeof(uint16_t));
            offset += sizeof(uint16_t);
            final_msg[offset++] = cur->lsig;
            memcpy(final_msg + offset, cur->sig, cur->lsig);
            offset += cur->lsig;
            cur = cur->next;
        }

        if (send_msg_enchere(final_msg, offset, p.enchere_active, 
                           p.encheres[p.enchere_active].sock) < 0) {
            fprintf(stderr, "Error sending initial consensus message\n");
            free(supervisor_signature);
            free_valid_peer_list(head);
            return -1;
        }

        // Prepare arrays for msg_20
        uint16_t peer_ids[MAX_PEERS];
        uint8_t sig_lengths[MAX_PEERS];
        uint8_t *signatures[MAX_PEERS];
        int num_validations = 0;

        // Collect validation data
        cur = head;
        while (cur && num_validations < MAX_PEERS) {
            peer_ids[num_validations] = cur->id;
            sig_lengths[num_validations] = cur->lsig;
            signatures[num_validations] = cur->sig;
            num_validations++;
            cur = cur->next;
        }

        // Send message 20 with all validations
        uint8_t msg20[BUF_SIZE];
        int msg20_len = msg_20(msg20, p.id_peer, num_validations, peer_ids, sig_lengths, signatures);
        
        if (send_msg_enchere(msg20, msg20_len, p.enchere_active, 
                           p.encheres[p.enchere_active].sock) < 0) {
            fprintf(stderr, "Error sending additional validation message\n");
            free(supervisor_signature);
            free_valid_peer_list(head);
            return -1;
        }
    }

    // Clean up
    free(supervisor_signature);
    free_valid_peer_list(head);

    // Remove absent peers from participant list
    for (int i = 0; i < num_absent; i++) {
        supp_peer_list(&p.encheres[p.enchere_active].liste_participants, absent_peer_ids[i]);
        p.encheres[p.enchere_active].nb_pairs--;
    }

    return 0;
}
