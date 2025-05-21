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
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <ifaddrs.h>
#include <poll.h>
#include <sys/time.h>

#include "../include/peer.h"
#include "../include/superviseur.h"
#include "../include/enchere.h"
#include "../include/message.h"
#include "../include/connexion.h"
#include "../include/utils.h"
#include "../include/securite.h"


//info superviseur 
int is_superviseur=0;
int enchere_supervise=0;
Peer p = {0}; // Structure pour stocker les informations du pair


// Gestion de la déconnexion propre avec Ctrl+C
void handle_sigint(int sig) {
    // utiliser sig pour enlever les warnings
    (void)sig;
    char leave_msg[BUF_SIZE];
    snprintf(leave_msg, sizeof(leave_msg), "[LEAVE] %s a quitté le groupe.\n", p.pseudo);

    if (send_multicast(p.adr_liaison.sock,leave_msg, strlen(leave_msg)) != 0) {
        fprintf(stderr, "Erreur lors de l'envoi du message de départ.\n");
    }

    if (is_superviseur) {
        cleanup_auction_supervisor(); // Clean up supervisor state if we were a supervisor
    }

    clean_peer();
    exit(0);
}


void peer_start(const char *nom) {

    p.enchere_active = -1; // Aucune enchère active au départ
    p.global_iface_index = get_active_interface();
    if (p.global_iface_index == -1) {
        fprintf(stderr, "Erreur : Aucune interface réseau active trouvée.\n");
        exit(EXIT_FAILURE);
    }

    // Générer l'ID et le p.pseudo du pair
    p.id_peer = generer_id_peer();
    p.pseudo = strdup(nom);
    if (p.pseudo == NULL) {
        perror("Erreur d'allocation mémoire pour le p.pseudo");
        exit(EXIT_FAILURE);
    }

// -----------------------------  SECURITE  -------------------------------------------------------
    init_openssl();
    char ed_pub[256], ed_priv[256];
    snprintf(ed_pub, sizeof(ed_pub), "%s_ed_pubKey.pem", p.pseudo);
    snprintf(ed_priv, sizeof(ed_priv), "%s_ed_privKey.pem", p.pseudo);
     // Générer et enregistrer les clés ED25519
    if (generate_ed25519_key(ed_pub, ed_priv)) {
        p.ed_privkey = convert_private_key_to_evp_pkey(ed_priv);
        // prive pour signature 
        /*
        	// signature 
        unsigned char *signature
        if(sign(pkey, msg, &signature, &slen)){
            printf("signature effectuée ! - longueurs : msg : %lu sign : %zu \n", strlen((char *) msg), slen);
            printf("\n");
        }
            //nettoyage 
            if(signature != NULL)
            free(signature);
        */
       p.ed_pubkey = convert_public_key_to_evp_pkey(ed_pub);
        /*
	    verify(pubkey, msg, signature, slen);
        */
           // Après avoir généré la clé privée "serv.key"
        // Générer un certificat auto-signé
        char cert_path[256];        
        snprintf(cert_path, sizeof(cert_path), "%s_cert.pem", p.pseudo);
        p.cert_path = strdup(cert_path);
        if (p.cert_path == NULL) {
            perror("Erreur d'allocation mémoire pour le cert_path");
            exit(EXIT_FAILURE);
        }
        if (!generer_certificat_autosigne(ed_priv, cert_path, p.pseudo)) {
            fprintf(stderr, "Erreur génération certificat auto-signé\n");
            exit(1);
        }
    //    generate_certificate_for_peer(p.pseudo, ed_pub, sizeof(ed_pub), ed_priv, sizeof(ed_priv));
        printf("Clés ED25519 générées et enregistrées avec succès.\n");
    } else {
        fprintf(stderr, "Erreur lors de la génération des clés ED25519.\n");
        free(p.pseudo);
        exit(EXIT_FAILURE);
    }

    if (p.ed_privkey == NULL || p.ed_pubkey == NULL) {
        fprintf(stderr, "Erreur lors du chargement des clés ED25519.\n");
        free(p.pseudo);
        exit(EXIT_FAILURE);
    }  

    p.ctx = SSL_CTX_new(TLS_server_method());
    if (!p.ctx) {
        fprintf(stderr, "Erreur lors de la création du contexte SSL.\n");
        free(p.pseudo);
        exit(EXIT_FAILURE);
    }

// ----------------------- Adresse perso IPv6 TCP/UDP ---------------------------------------------------------------

    char ip_str[INET6_ADDRSTRLEN];

    // Demander à l'utilisateur de saisir un port
    printf("Entrez le port perso (49152-65535) : ");
    if (scanf("%hu", &p.port_perso) != 1 || p.port_perso < 49152 || p.port_perso > 65535) {
        fprintf(stderr, "Port invalide. Le port doit être entre 49152 et 65535.\n");
        exit(EXIT_FAILURE);
    }

    if (get_ipv6_address(ip_str, sizeof(ip_str)) == 0) {
        printf("Adresse IPv6 perso trouvée : %s \n", ip_str);
        if (inet_pton(AF_INET6, ip_str, &p.adr_perso) != 1) {
            fprintf(stderr, "Erreur de conversion inet_pton\n");
            exit(EXIT_FAILURE);
        }
    } else {
        fprintf(stderr, "Impossible de trouver une adresse IPv6 valide.\n");
        exit(EXIT_FAILURE);
    }
    
    // Renseigner les champs obligatoires
    p.adr_perso.sin6_family = AF_INET6;
    p.adr_perso.sin6_port = htons(p.port_perso); // Port personnel saisi par l'utilisateur

    // Remplir l'adresse IPv6 depuis ip_str
    if (inet_pton(AF_INET6, ip_str, &p.adr_perso.sin6_addr) != 1) {
        fprintf(stderr, "Erreur de conversion inet_pton\n");
        exit(EXIT_FAILURE);
    }

    // Vérifier si l'adresse est de type lien-local
    if (IN6_IS_ADDR_LINKLOCAL(&p.adr_perso.sin6_addr)) {
        p.adr_perso.sin6_scope_id = p.global_iface_index; // Utiliser le scope ID pour les adresses lien-local
    }
    p.adr_perso.sin6_scope_id = p.global_iface_index;

    // Création sockets perso (TCP & UDP)
    if (create_perso_adr_sockets(p.adr_perso, p.global_iface_index, &p.socket_tcp, &p.socket_udp, p.port_perso) != 0) {
    // if (create_perso_adr_sockets(p.adr_perso, p.global_iface_index, &p.socket_tcp, &p.socket_udp, p.port_perso, ed_priv) != 0) {
        printf("test:%d\n",p.global_iface_index);
        fprintf(stderr, "Erreur lors de la création des sockets perso TCP/UDP.\n");
        exit(EXIT_FAILURE);
    }

// ------------------------------- MULTICAST ---------------------------------------------------
    // Création du socket UDP IPv6
    p.adr_liaison.sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (p.adr_liaison.sock < 0) {
        perror("socket multicast");
        free(p.pseudo);
        exit(EXIT_FAILURE);
    }

    // Préparation de l'adresse de liaison
    p.adr_liaison.addr.sin6_family = AF_INET6;
    p.adr_liaison.addr.sin6_port = htons(PORT);
    p.adr_liaison.addr.sin6_addr = in6addr_any;  // liaison sur toutes les adresses locales

    // Réutilisation d'adresse et de port
    int reuse = 1;
    if (setsockopt(p.adr_liaison.sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt multicast SO_REUSEADDR");
        close(p.adr_liaison.sock);
        free(p.pseudo);
        exit(EXIT_FAILURE);
    }
    if (setsockopt(p.adr_liaison.sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt multicast SO_REUSEPORT");
        close(p.adr_liaison.sock);
        free(p.pseudo);
        exit(EXIT_FAILURE);
    }

    // Liaison du socket
    if (bind(p.adr_liaison.sock, (struct sockaddr *)&p.adr_liaison.addr, sizeof(p.adr_liaison.addr)) < 0) {
        perror("bind multicast");
        clean_peer();
        exit(EXIT_FAILURE);
    }

    // Conversion de l'adresse multicast (ex: ff02::abcd)
    if (inet_pton(AF_INET6, GROUP, &p.adr_liaison.mreq.ipv6mr_multiaddr) != 1) {
        perror("inet_pton multicast");
        clean_peer();
        exit(EXIT_FAILURE);
    }

    // Définition de l'interface multicast (ex: en0)
    p.adr_liaison.mreq.ipv6mr_interface = p.global_iface_index;

    // Abonnement au groupe multicast
    if (setsockopt(p.adr_liaison.sock, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                &p.adr_liaison.mreq, sizeof(p.adr_liaison.mreq)) < 0) {
        perror("setsockopt IPV6_JOIN_GROUP");
        clean_peer();
        exit(EXIT_FAILURE);
    }

    // Initialisation de l'adresse de destination pour l'envoi
    if (inet_pton(AF_INET6, GROUP, &p.adr_liaison.addr.sin6_addr) != 1) {
        perror("inet_pton multicast");
        clean_peer();
        exit(EXIT_FAILURE);
    }

    // Ajout du scope ID pour une adresse link-local (obligatoire pour ff02::)
    p.adr_liaison.addr.sin6_scope_id = p.global_iface_index;

    printf("Abonné au groupe multicast %s sur l'interface %d\n", GROUP, p.global_iface_index);


    // Gestion du signal
    signal(SIGINT, handle_sigint);

// --------------------------------------------------------------------------------
    // Message de JOIN
    char join_msg[BUF_SIZE];
    snprintf(join_msg, sizeof(join_msg), "[JOIN] %s a rejoint le groupe.\n", nom);
    
    if (send_multicast(p.adr_liaison.sock, join_msg, strlen(join_msg)) < 0) {
        fprintf(stderr, "Erreur lors de l'envoi du message de JOIN.\n");
        close(p.adr_liaison.sock);
        exit(EXIT_FAILURE);
    }

    // État du listener TCP
    p.listener_tcp.socket_tcp = p.socket_tcp;
    p.listener_tcp.socket_udp = p.socket_udp;
    p.listener_tcp.response_received = 0;
    p.listener_tcp.first_response_time = 0;

    pthread_t tcp_thread;
    pthread_create(&tcp_thread, NULL, listen_tcp_thread, &p.listener_tcp);

    // gestion_socket();
    pthread_t t_principal;
    pthread_create(&t_principal, NULL, listen_main_sockets, NULL);

    // Attendre la fin des threads
    pthread_join(tcp_thread, NULL);
    pthread_join(t_principal, NULL);
    clean_peer();
    exit(EXIT_SUCCESS);
}

// -------------------  GESTION DES 3 SOCKETS PRINCIPALES ------------------------------------------
// -------------------- ( Liaison/GROUP - UDP - TCP  )-------------------------------------------

void *listen_tcp_thread(void *arg) {
    struct tcp_listener_state *state = arg;

    while (1) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(state->socket_tcp, &readfds);
        struct timeval timeout = { .tv_sec = 1, .tv_usec = 0 };

        if (select(state->socket_tcp + 1, &readfds, NULL, NULL, &timeout) > 0 &&
            FD_ISSET(state->socket_tcp, &readfds)) {

            struct sockaddr_in6 client_addr;
            socklen_t addr_len = sizeof(client_addr);
            
            int client_sock = accept(state->socket_tcp, (struct sockaddr *)&client_addr, &addr_len);
            if (client_sock < 0) {
                perror("accept");
                continue;
            }
            // SSL *ssl = SSL_new(p.ctx); 
            // if (!ssl) {
            //     fprintf(stderr, "Erreur lors de la création de l'objet SSL.\n");
            //     close(client_sock);
            //     continue;
            // }
            // SSL_set_fd(ssl, client_sock);
            // if (SSL_accept(ssl) <= 0) {
            //     fprintf(stderr, "Erreur lors de l'acceptation de la connexion SSL.\n");
            //     ERR_print_errors_fp(stderr);
            //     SSL_shutdown(ssl);
            //     close(client_sock);
            //     SSL_free(ssl);
            //     continue;
            // }

            // printf ("connexion SSL/TLS avec %s --- %s\n", SSL_get_cipher(ssl), SSL_get_cipher_version(ssl));

            // Peek 1er octet sans consommer
            uint8_t peekbuf[1];
            ssize_t peeklen = recv(client_sock, peekbuf, 1, MSG_PEEK);
            // ssize_t peeklen = SSL_peek(ssl, peekbuf, sizeof(peekbuf));
            if (peeklen <= 0) {
                close(client_sock);
                continue;
            }

            if (peekbuf[0] == 4) {
                // Connexion TCP simple (message 4 attendu)
                uint8_t buffer[BUF_SIZE];
                ssize_t len = recv(client_sock, buffer, BUF_SIZE, 0);
                // ssize_t len = SSL_read(ssl, buffer, sizeof(buffer));
                if (len <= 0) {
                    /* libération des ressources */
                    // cleanup_ssl_connection(ssl);
                    close(client_sock);
                    continue;
                }
                if (buffer[0] == 4 && p.num_peers >= 0) {
                    struct message_4 parsed_msg;
                    if (parse_msg_4(buffer, len, &parsed_msg) == 0) {
                        p.discovered_peers[p.num_peers++] = (struct peer_info){
                            .id = parsed_msg.id,
                            .ip = parsed_msg.ip,
                            .port_tcp = parsed_msg.port
                        };
                        char ip_str[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6, &p.discovered_peers[p.num_peers-1].ip, ip_str, sizeof(ip_str));
                        printf("Message 4 reçu : ID=%u, IP=%s, PORT=%u\n",p.discovered_peers[p.num_peers-1].id,
                               ip_str, (p.discovered_peers[p.num_peers-1].port_tcp));
                        state->response_received = true;
                        state->first_response_time = time(NULL);
                    }
                }
                // cleanup_ssl_connection(ssl);
                close(client_sock);

            } else if (peekbuf[0] == 5) {
                // Connexion TCP avec message 5
                uint8_t buffer[BUF_SIZE];
                ssize_t len = recv(client_sock, buffer, BUF_SIZE, 0);
                // ssize_t len = SSL_read(ssl, buffer, sizeof(buffer));
                if (len <= 0) {
                    // cleanup_ssl_connection(ssl);
                    close(client_sock);
                    continue;
                }
                if (len > 0 && buffer[0] == 5) {
                    struct message_5 parsed_msg;
                    if (parse_msg_5(buffer, len, &parsed_msg) == 0) {
                        printf("Message 5 reçu : ID=%u,  PORT=%u\n", parsed_msg.id,
                               (parsed_msg.port));
                        state->response_received = true;
                        state->first_response_time = time(NULL);
                        
                        // Vérifier si l'ID existe déjà
                        bool id_exists = false;
                        int count=0;
                        int position_enr=0;
                        for (int i = 0; i < p.num_peers; ++i) {
                            if (p.discovered_peers[i].id == parsed_msg.id) {
                                count++;
                            }
                            if(count==2){
                                id_exists = true;
                                position_enr=i;
                                break;
                            }
                        } if (id_exists==false && p.num_peers < MAX_PEERS) {
                            
                            uint8_t msg[1];
                            int msg_len = msg_50(msg);

                            if (send(client_sock, msg, msg_len, 0) != msg_len) {
                            // if (SSL_write(ssl, msg, msg_len) != msg_len) {
                                perror("send msg_50");
                            } else {
                                printf("Message 50 envoyé à %s:%u avec ID=%u\n",
                                inet_ntoa(*(struct in_addr *)&parsed_msg.ip),
                                ntohs(parsed_msg.port),parsed_msg.id);
                            }
                        }else{
                            uint16_t new_id = (int)rand()%25;  // À revoir
                            uint8_t msg[3];
                            int msg_len = msg_51(msg, new_id);

                            if (send(client_sock, msg, msg_len, 0) != msg_len) {
                            // if (SSL_write(ssl, msg, msg_len) != msg_len) {
                                perror("send msg_51");
                            } else {
                                printf("Message 51 envoyé à %s:%u avec nouvel ID=%u\n",inet_ntoa(*(struct in_addr *)&parsed_msg.ip),ntohs(parsed_msg.port), new_id);
                                parsed_msg.id=new_id;
                            }
                        }
        
                        // Envoi du message 7 à P pour rejoindre l'enchere
                        uint8_t buffer[BUF_SIZE];
                        memset(buffer, 0, sizeof(buffer));
                        // GERE LE NOMBRE
                        // int taille = msg_7(buffer, sizeof(buffer), encheres[0], 1);
                        int taille = message_7_header(buffer, sizeof(buffer), p.encheres[0]);
                        // Envoi du message 7 à P en plusieurs parties
                        size_t total_sent = 0;
                        while (total_sent < taille) {
                            ssize_t sent = send(client_sock, buffer + total_sent, taille - total_sent, 0);
                            // ssize_t sent = SSL_write(ssl, buffer + total_sent, taille - total_sent);
                            if (sent < 0) {
                                perror("Erreur d'envoi du message");
                                // cleanup_ssl_connection(ssl);
                                close(client_sock);
                                return NULL;
                            }
                            total_sent += sent;
                        }

                        if (total_sent == taille) {
                            printf("Message 7 header envoyé à P avec succès (%zu octets).\n", total_sent);
                        } else {
                            fprintf(stderr, "Erreur : message incomplet envoyé (%zu/%d octets).\n", total_sent, taille);
                        }

                        //  ENVOI des infos des pairs
                        printf("Envoi des infos des pairs à P...\n");
                        print_peer_list(p.encheres[0].liste_participants);
                        envoyer_infos_peers(client_sock, &p.encheres[0]);

                        printf("Message 7 envoyé à P SUCCES.\n");
                        shutdown(client_sock, SHUT_WR);

                        // VERIFIE QUE P A REJOINT l'ENCHERE AVANT AJOUT 
                        uint8_t stop [BUF_SIZE];
                        ssize_t len = recv(client_sock, stop, BUF_SIZE, 0);
                        // ssize_t len = SSL_read(ssl, stop, sizeof(stop));
                        if (len > 0) {
                            stop[len] = '\0';
                            printf("Message reçu de P : %s\n", stop);
                            // cleanup_ssl_connection(ssl);
                            close(client_sock);
                            continue;
            
                        } else if (len == 0) {
                            printf("Connexion fermée par le pair.\n");
                        } else {
                            perror("recv");
                        }
                        // cleanup_ssl_connection(ssl);
                        close(client_sock);

                        printf("\n\n");
                        //Message 6, connexion aux autres peers
                        printf("id=%d\n",parsed_msg.id);
                        printf("nb participants enchere %d\n", p.encheres[p.enchere_active].nb_pairs);
                        if (p.encheres[p.enchere_active].nb_pairs == 1){
                            printf("enchere avec une personne\n");
                        } else {
                            printf("nb participants enchere %d\n", p.encheres[p.enchere_active].nb_pairs);
                            connect_to_peers_and_send_info(p.encheres[p.enchere_active].liste_participants,parsed_msg.id,parsed_msg.ip,parsed_msg.port,parsed_msg.cle);
                            printf("envoye a tous is good\n");                            
                        }

                        add_peer(&p.encheres[p.enchere_active].liste_participants,parsed_msg.id,parsed_msg.ip,parsed_msg.port,parsed_msg.cle);
                        p.encheres[p.enchere_active].nb_pairs++;                       
                        printf("nb participants enchere %d\n", p.encheres[p.enchere_active].nb_pairs);
                    }
                }

            } else if(peekbuf[0] == 6){
                printf("MESSAGE 6 RECU\n");
                uint8_t buffer[BUF_SIZE];
                ssize_t len = recv(client_sock, buffer, BUF_SIZE, 0);
                // ssize_t len = SSL_read(ssl, buffer, sizeof(buffer));
                if (len <= 0) {
                    // cleanup_ssl_connection(ssl);
                    close(client_sock);
                    continue;
                }
                buffer[len] = '\0';
                struct message_6 msg={0};
                if(parse_msg_6(buffer,sizeof(msg),&msg)<0){
                    printf("erreur message 6 reception\n");
                }
                add_peer(&p.encheres[p.enchere_active].liste_participants,msg.id,msg.ip,msg.port,msg.cle);
                p.encheres[p.enchere_active].nb_pairs++;
                printf("info message 6 recu paire ajouté : %d\n", p.encheres[p.enchere_active].nb_pairs);
                // cleanup_ssl_connection(ssl);
                close(client_sock);
                continue;
            }
                printf("Message inattendu reçu : %u\n", peekbuf[0]);
                // cleanup_ssl_connection(ssl);
                close(client_sock);
        }

    } 
    return NULL;         
}

   
int gestion_reception_liaison() {
    char buf[1024];
    struct sockaddr_in6 src;
    socklen_t len = sizeof(src);
    ssize_t n = recvfrom(p.adr_liaison.sock, buf, sizeof(buf), 0,
                         (struct sockaddr*)&src, &len);
    if (n < 0) {
        perror("recvfrom");
        return -1;
    }
    if (n == 0) {
        // Pas de données reçues
        return 1;
    }

    buf[n] = '\0';

    // Gestion des messages binaires avec code
    uint8_t code = (uint8_t)buf[0];

    // Protocole pour rejoindre un système d'enchères
    if (code == 3 && p.nb_encheres > 0) {
        uint8_t msg[1 + 2 + 16 + 2];
         if (msg_4(msg, p.id_peer, p.port_perso) != 0) {
             fprintf(stderr, "Erreur lors de la construction du message 4.\n");
             return -1;
         }

         if (sendto(p.socket_udp, msg, sizeof(msg), 0,
                (struct sockaddr*)&src, len) < 0) {
              perror("sendto");
            return -1; 
    
         } else {
             // Afficher l'adresse et le port source
             char ip_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &src.sin6_addr, ip_str, sizeof(ip_str));
            printf("Message send a [%s]:%d\n", ip_str, ntohs(src.sin6_port));
        }
        return 0;
    } 

    // Traitement texte normal
    printf("[Multicast] %s\n", buf);
    fflush(stdout);

    // Exemple de gestion de validation
    if (strncmp(buf, "[VALIDATION]", 12) == 0) {
        char *msg = strchr(buf, ' ') + 1;
        char *sig_str = strchr(msg, ' ') + 1;
        unsigned char sig[256];
        size_t siglen = strlen(sig_str) / 2;
        for (size_t i = 0; i < siglen; i++) {
            sscanf(sig_str + 2 * i, "%2hhx", &sig[i]);
        }

        EVP_PKEY *peer_pubkey = get_peer_pubkey(p.pseudo);
        if (peer_pubkey && verify_message(peer_pubkey, (unsigned char *)msg, strlen(msg), sig, siglen)) {
            printf("Message validé par %s\n", p.pseudo);
        } else {
            printf("Échec de la vérification du message de %s\n", p.pseudo);
        }
    }
    return 0;
}

int gestion_reception_UDP() {
    uint8_t buf[1024];
    struct sockaddr_in6 src = {0};
    socklen_t len = sizeof(src);
    ssize_t n = recvfrom(p.socket_udp, buf, sizeof(buf), 0,
                         (struct sockaddr*)&src, &len);
    if (n < 0) {
        perror("recvfrom");
        return -1;
    }
    if (n == 0) {
        printf("Pas de données reçues\n");
        return 1;
    }

    buf[n] = '\0';
    // Gestion des messages avec code
    if (buf[0] == 4 && p.num_peers >= 0) {
        struct message_4 parsed_msg;
        if (parse_msg_4(buf, len, &parsed_msg) == 0)
        {
            p.discovered_peers[p.num_peers++] = (struct peer_info){
                .id = parsed_msg.id,
                .ip = parsed_msg.ip,
                .port_tcp = (parsed_msg.port)};
            p.listener_tcp.response_received = true;
            p.listener_tcp.first_response_time = time(NULL);
            char ip_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &p.discovered_peers[p.num_peers - 1].ip, ip_str, sizeof(ip_str));
            printf("Pair découvert : ID=%u, IP=%s, Port TCP=%u\n",
                   p.discovered_peers[p.num_peers-1].id, ip_str, p.discovered_peers[p.num_peers - 1].port_tcp);

            if (p.num_peers > 0) {
                struct peer_info *peer_Q = &p.discovered_peers[0];
                char ip_str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &peer_Q->ip, ip_str, sizeof(ip_str));
                uint16_t port = (peer_Q->port_tcp);
                printf("Connexion à : ID=%u, IP=%s, PORT=%u\n", peer_Q->id, ip_str, port);

                // connexion qui doit rester ouverte, stocker le return de x=connexion_TLS et voir comment gerer ca
                int socket_P = connexion_TLS(peer_Q->ip, port);
                // SSL *ssl = connexion_TLS(peer_Q->ip, port);
                // if (ssl == NULL) {
                //     fprintf(stderr, "Erreur lors de la connexion TLS.\n");
                //     return -1;
                // }
                // int socket_P = SSL_get_fd(ssl);
                // if (socket_P < 0){
                //     close(socket_P);
                //     printf("Erreur connexion à Q\n");
                //     return -1;
                // }

                printf("Je suis ds msg_join étape 7\n");

                // RECEVOIR MESSAGE 7
                if (recevoir_message_7_header(socket_P, &p.encheres[p.nb_encheres]) != 0) {
                    fprintf(stderr, "Erreur lors de la réception du message 7.\n");
                    close(socket_P);
                    return -1;
                }
                sleep(1);

                if (&p.encheres[p.enchere_active] == NULL) {
                    fprintf(stderr, "Erreur : enchère active non initialisée.\n");
                    return -1;
                }

                p.encheres[p.nb_encheres].liste_participants = NULL;
            
                printf("nb pairs %d\n", p.encheres[p.nb_encheres].nb_pairs);
                for (int i = 0; i < p.encheres[p.nb_encheres].nb_pairs; i++) {
                    if (recevoir_infos_peer(socket_P, &p.encheres[p.nb_encheres]) != 0) {
                        fprintf(stderr, "Erreur lors de l'ajout du pair à la liste.\n");
                        close(socket_P);
                        return -1;
                    }
                }

                int enchere_precedente = p.enchere_active; // Enchère précédente
                p.enchere_active = p.nb_encheres; // Indique que nous avons rejoint l'enchère active
                // Print the decoded message details
                char str_ip[INET6_ADDRSTRLEN];
                if (inet_ntop(AF_INET6, &p.encheres[p.enchere_active].group, str_ip, sizeof(str_ip)) == NULL) {
                    perror("inet_ntop");
                    close(socket_P);
                    // cleanup_ssl_connection(ssl);
                    return -1;
                }
                printf("Message 7 reçu : ID_Q=%d, IP_enchere=%s, PORT_enchere=%d\n", 
                    p.encheres[p.enchere_active].id_enchere,
                    str_ip,
                    p.encheres[p.enchere_active].port_enchere);

                // Join the auction with the received information
                if (join_enchere(p.encheres[p.enchere_active].id_enchere, 
                                str_ip, 
                                p.encheres[p.enchere_active].port_enchere) != 0) {
                    fprintf(stderr, "Erreur lors de la jointure de l'enchère.\n");
                    memset(&p.encheres[p.enchere_active], 0, sizeof(EnchereSocket));
                    p.enchere_active = enchere_precedente; // Reset active auction
                    send(socket_P, "erreur", 6, 0);
                    // SSL_write(socket_P, "erreur", 6);
                    close(socket_P);
                    // cleanup_ssl_connection(ssl);
                    return -1;
                }
                //printf("nb de pairs enchere %d\n",p.encheres[p.enchere_active].nb_pairs);
                close(socket_P);
                // cleanup_ssl_connection(ssl);
        return 0;
    }

    printf("Aucune enchère trouvée. Création d'une nouvelle.\n");
    creer_enchere();
            return 0;
        }
    } else if (buf[0] == 1) {
        printf("verif du msg 1 consensus\n");
    }
    printf("[Unicast UDP] %s\n", buf);
    fflush(stdout);

    return 0;
}

int gestion_reception_TCP(int client_fd, struct tcp_listener_state* listener) {
    printf("Gestion de la réception TCP...\n");
    struct sockaddr_in6 client_addr = {0};
    socklen_t addr_len = sizeof(client_addr);

    uint8_t peekbuf[1];
    ssize_t peeklen = recv(client_fd, peekbuf, 1, MSG_PEEK);
    if (peeklen <= 0) {
        close(client_fd);
        perror("recv");
        return -1;
    }
    else if (peekbuf[0] == 5) {
        // Message 5
        uint8_t buffer[BUF_SIZE];
        ssize_t len = recv(client_fd, buffer, BUF_SIZE, 0);
        if (len > 0 && buffer[0] == 5)
        {
            struct message_5 parsed_msg;
            if (parse_msg_5(buffer, len, &parsed_msg) == 0)
            {
                printf("Message 5 reçu : ID=%u, PORT=%u\n", parsed_msg.id, ntohs(parsed_msg.port));
                listener->response_received = true;
                listener->first_response_time = time(NULL);

                bool id_exists = false;
                int count = 0, position_enr = 0;
                for (int i = 0; i < p.num_peers; ++i)
                {
                    if (p.discovered_peers[i].id == parsed_msg.id)
                        count++;
                    if (count == 2)
                    {
                        id_exists = true;
                        position_enr = i;
                        break;
                    }
                }

                if (!id_exists && p.num_peers < MAX_PEERS)
                {
                    uint8_t msg[1];
                    int msg_len = msg_50(msg);
                    if (send(client_fd, msg, msg_len, 0) != msg_len)
                        perror("send msg_50");
                    else
                        printf("Message 50 envoyé à %s:%u avec ID=%u\n",
                                inet_ntoa(*(struct in_addr *)&parsed_msg.ip),
                                ntohs(parsed_msg.port), parsed_msg.id);
                }
                else {
                    uint16_t new_id = rand() % 25;
                    uint8_t msg[3];
                    int msg_len = msg_51(msg, new_id);
                    if (send(client_fd, msg, msg_len, 0) != msg_len) {
                        perror("send msg_51");
                    } else {
                        printf("Message 51 envoyé à %s:%u avec nouvel ID=%u\n",
                                inet_ntoa(*(struct in_addr *)&parsed_msg.ip),
                                ntohs(parsed_msg.port), new_id);
                        p.discovered_peers[position_enr].id = new_id;
                    }
                }

                // Envoi du message 7
                uint8_t msg7_buf[BUF_SIZE];
                int taille = message_7_header(msg7_buf, sizeof(msg7_buf), p.encheres[0]);
                size_t total_sent = 0;
                while (total_sent < taille)
                {
                    ssize_t sent = send(client_fd, msg7_buf + total_sent, taille - total_sent, 0);
                    if (sent < 0)
                    {
                        perror("Erreur d'envoi du message");
                        close(client_fd);
                        return -1;
                    }
                    total_sent += sent;
                }

                printf("Message 7 header envoyé (%zu octets).\n", total_sent);
                print_peer_list(p.encheres[0].liste_participants);
                envoyer_infos_peers(client_fd, &p.encheres[0]);
                close(client_fd);
                return 0;
            }
        }
    } else {
        // Autres messages
        char buffer[BUF_SIZE];
        ssize_t len = recv(client_fd, buffer, sizeof(buffer), 0);
        if (len > 0) {
            buffer[len] = '\0';
            printf("[TCP] %s\n", buffer);
            fflush(stdout);
        }
    }
    close(client_fd);
    return 0;
}


void* listen_main_sockets(void* arg) {
    struct pollfd fds[3] = {0};
    int n = 3;

    fds[0].fd = p.adr_liaison.sock;  // Multicast
    fds[0].events = POLLIN;

    fds[1].fd = p.socket_udp;        // Unicast UDP
    fds[1].events = POLLIN;

    fds[2].fd = STDIN_FILENO;        // Claver
    fds[2].events = POLLIN;

    // fds[3].fd = p.socket_tcp;      // TCP
    // fds[3].events = POLLIN;

    while (1) {
        int ret = poll(fds, n, -1);  

        if (ret < 0) {
            perror("poll");
            break;
        }

        // SOCKET MULTICAST
        if (fds[0].revents & POLLIN) {
            if (gestion_reception_liaison() < 0) {
                fprintf(stderr, "Erreur lors de la réception du message multicast.\n");
            }
        }

        // SOCKET UNICAST UDP
        if (fds[1].revents & POLLIN) {
            if (gestion_reception_UDP() < 0) {
                fprintf(stderr, "Erreur lors de la réception du message unicast.\n");
            }
        }

        // ENTRÉE CLAVIER
        if (fds[2].revents & POLLIN) {
            char input[BUF_SIZE];
            if (fgets(input, sizeof(input), stdin) != NULL) {
                size_t len = strlen(input);
                if (len > 0 && input[len - 1] == '\n') {
                    input[len - 1] = '\0'; // retirer le \n
                }

                if (strcmp(input, "lancer") == 0) {
                    creer_enchere();
                    continue;
                }
                else if (strcmp(input, "join") == 0) {
                    if (msg_join_enchere() == -1) {
                        printf("Erreur lors de l'envoi de la demande de rejoindre l'enchère.\n");
                    }
                    continue;
                }
                else if (strncmp(input, "offre ", 6) == 0) {
                    uint32_t prix;
                    if (sscanf(input + 6, "%u", &prix) == 1) {
                        faire_offre(prix);
                    } else {
                        printf("Format invalide. Utilisez: offre <prix>\n");
                    }
                    continue;
                }
                else if (strncmp(input, "help", 4) == 0) {
                    printf("Commandes disponibles:\n");
                    printf(" - lancer : Lancer une enchère\n");
                    printf(" - join : Rejoindre une enchère\n");
                    printf(" - offre <prix> : Faire une offre\n");
                    printf(" - encheres : Afficher les enchères avec vente\n");
                    printf(" - vente : Initier une vente\n");
                    printf(" - offre : Surencherir\n");
                    printf(" - quit : Quitter le programme\n");
                    continue;
                }
                else if (strcmp(input, "quit") == 0) {
                    clean_peer();
                    printf("Quitter le programme...\n");
                    break;
                }
                else if (strcmp(input, "encheres") == 0) {
                    afficher_enncheres();
                    continue;
                }
                else if (strcmp(input, "vente") == 0) {
                    // Initier une vente
                    if (init_vente() == -1) {
                        printf("Erreur lors de l'initiation de la vente.\n");
                    }
                    printf("Vente initiée.\n");
                    continue;
                } 
                else if (strcmp(input, "offre") == 0) {
                    // Surencherir
                    if (sur_enchere() == -1) {
                        printf("Erreur lors de la surenchère.\n");
                    }
                    printf("Surenchère effectuée.\n");
                    continue;
                }
                else {
                    if (strlen(input) == 0) {
                        continue; // Ignore empty input
                    }
                    // Message par défaut
                    char message[BUF_SIZE];
                    snprintf(message, sizeof(message), "[%s] %s", p.pseudo, input);

                    if (p.enchere_active >= 0) {
                        if (send_msg_enchere(message, strlen(message), p.enchere_active) < 0) {
                            fprintf(stderr, "Erreur lors de l'envoi du message d'enchère\n");
                        }
                    } else {
                        // Envoi général au groupe principal
                        if (send_multicast(p.adr_liaison.sock ,message, strlen(message)) < 0) {
                            fprintf(stderr, "Erreur lors de l'envoi du message\n");
                        }
                    }
                }
            }

        }
    }

    return NULL;
}



// -------------------  ------------------------------------------

void clean_peer() {
    // Libérer le p.pseudo
    if (p.pseudo) {
        free(p.pseudo);
        p.pseudo = NULL;
    }

    // Libérer le certificat 
    if (p.cert_path) {
        free(p.cert_path);
        p.cert_path = NULL;
    }

    
    // Fermer les sockets personnels
    if (p.socket_tcp >= 0) {
        close(p.socket_tcp);
        p.socket_tcp = -1;
    }

    if (p.socket_udp >= 0) {
        close(p.socket_udp);
        p.socket_udp = -1;
    }

    // Fermer la socket globale (multicast de découverte)
    if (p.adr_liaison.sock >= 0) {
        close(p.adr_liaison.sock);
        p.adr_liaison.sock = -1;
    }

    // Quitter le groupe multicast d’une enchère si nécessaire
    if (p.adr_liaison.sock >= 0) {
        // Se désabonner du groupe multicast
        setsockopt(p.adr_liaison.sock, IPPROTO_IPV6, IPV6_LEAVE_GROUP,
                   &p.adr_liaison.mreq, sizeof(p.adr_liaison.mreq));
        close(p.adr_liaison.sock);
        p.adr_liaison.sock = -1;
    }

    // Quitter toutes les enchères (groupes multicast) et fermer les sockets
    for (int i = 0; i < p.nb_encheres; i++) {
        if (p.encheres[i].sock >= 0) {
            struct ipv6_mreq mreq;
            memset(&mreq, 0, sizeof(mreq));
            memcpy(&mreq.ipv6mr_multiaddr, &p.encheres[i].group, sizeof(struct in6_addr));
            mreq.ipv6mr_interface = p.global_iface_index;

            // Se désabonner proprement du groupe multicast
            if (setsockopt(p.encheres[i].sock, IPPROTO_IPV6, IPV6_LEAVE_GROUP, &mreq, sizeof(mreq)) < 0) {
                perror("setsockopt IPV6_LEAVE_GROUP");
            }

            close(p.encheres[i].sock);
            p.encheres[i].sock = -1;

            // Libération de la liste des participants si allouée dynamiquement
            free_peer_list(p.encheres[i].liste_participants);  // à implémenter si nécessaire
            p.encheres[i].liste_participants = NULL;
        }
    }
    if (p.ed_privkey) EVP_PKEY_free(p.ed_privkey);
    if (p.ed_pubkey) EVP_PKEY_free(p.ed_pubkey);
    SSL_CTX_free(p.ctx);

    printf("Peer nettoyé proprement.\n");
}



// Function to connect to all other peers and send message 6
 int connect_to_peers_and_send_info(peer_list *h, uint16_t new_peer_id, struct in6_addr new_peer_ip, 
                                  uint16_t new_peer_port, unsigned char *new_peer_cle) {
     int ret = 0;
    peer_list *current = h->next;
    
     while (current != NULL) {
         // Create TLS connection to the peer
         if(current->id==p.id_peer){
            current=current->next;
            continue;
         }
         int sock = connexion_TCP(current->ip, current->port_tcp);
         if (sock < 0) {
             fprintf(stderr, "Failed to create TLS connection to peer %d\n", current->id);
             current = current->next;
             continue;
         }

        // SSL *ssl = SSL_new(p.ctx);
        // if (!ssl) {
        //     fprintf(stderr, "Failed to create SSL object\n");
        //     close(sock);
        //     current = current->next;
        //     continue;
        // }
        // SSL_set_fd(ssl, sock);
        // if (SSL_connect(ssl) <= 0) {
        //     fprintf(stderr, "Failed to establish SSL connection\n");
        //     SSL_free(ssl);
        //     close(sock);
        //     current = current->next;
        //     continue;
        // }


         // Create and send message 6
         uint8_t msg[1 + 2 + 16 + 2 + 113];  // CODE + ID + IP + PORT + CLE
         int msg_len = msg_6(msg, new_peer_id, new_peer_ip, new_peer_port, new_peer_cle);
         printf("id:%d,port\n",msg[msg_len]);
        
         if (send(sock, msg, msg_len, 0) != msg_len) {
            // if (SSL_write(ssl, msg, msg_len) != msg_len) {
                fprintf(stderr, "Failed to send message 6 to peer %d\n", current->id);
                // cleanup_ssl_connection(ssl);
                close(sock);
                current = current->next;
                continue;
         }

        // Read response
         uint8_t response[2];
         int bytes_read = recv(sock, response, 2, 0);
            // int bytes_read = SSL_read(ssl, response, sizeof(response));
         if (bytes_read == 0) {
            printf("envoye ok msg 6\n");
            // cleanup_ssl_connection(ssl);
            close(sock);
            current = current->next;
            continue;
         }

        // cleanup_ssl_connection(ssl);
        close(sock);
         current = current->next;
     }

     return ret;
}

// Function to handle a new peer connection (message 5)
// int handle_new_peer(struct peer *p, SSL *ssl, uint8_t *msg, size_t msg_len) {
//     struct message_5 msg_struct;
//     if (parse_msg_5(msg, msg_len, &msg_struct) != 0) {
//         return -1;
//     }

//     // Check if ID is already taken
//     uint16_t assigned_id = msg_struct.id;
//     if (find_peer_id(p, &assigned_id, false)) {
//         // Send error response (code 51)
//         uint8_t response[1] = {51};
//         SSL_write(ssl, response, 1);
//         return -1;
//     }

//     // Send success response with assigned ID (code 50)
//     uint8_t response[3] = {50, (assigned_id >> 8) & 0xFF, assigned_id & 0xFF};
//     SSL_write(ssl, response, 3);

//     // Connect to all other peers and send the new peer's information
//     if (connect_to_peers_and_send_info(p, assigned_id, msg_struct.ip, 
//                                      msg_struct.port, msg_struct.cle) != 0) {
//         return -1;
//     }

//     // Add the new peer to our list
//     return add_peer(p, assigned_id, msg_struct.ip, msg_struct.port, msg_struct.cle);
// }

// int find_peer_id(struct peer *p, uint16_t *id, bool find_free) {
//     if (!p || !id) return -1;

//     // If we're checking if an ID is taken
//     if (!find_free) {
//         struct peer *current = p->next;
//         while (current != p) {
//             if (current->id == *id) {
//                 return 1; // ID is taken
//             }
//             current = current->next;
//         }
//         return 0; // ID is free
//     }

//     // If we're looking for a free ID
//     uint16_t start_id = 1;
//     uint16_t end_id = 65535;
    
//     // First try the requested ID if provided
//     if (*id != 0) {
//         if (!find_peer_id(p, id, false)) {
//             return 0; // Requested ID is free
//         }
//         start_id = *id + 1;
//     }

//     // Search for a free ID
//     for (uint16_t test_id = start_id; test_id <= end_id; test_id++) {
//         if (!find_peer_id(p, &test_id, false)) {
//             *id = test_id;
//             return 0;
//         }
//     }

//     return -1; // No free ID found
// }

int add_peer(peer_list **head, uint16_t id, struct in6_addr ip, uint16_t port, unsigned char *cle) {
    peer_list *new_peer = malloc(sizeof(peer_list));
    if (!new_peer) {
        perror("Erreur d'allocation mémoire pour le peer");
        return -1;
    }

    new_peer->id = id;
    new_peer->ip = ip;
    new_peer->port_tcp = port;
    if (cle != NULL) {
        memcpy(new_peer->cle, cle, 113);
    } else {
        memset(new_peer->cle, 0, 113);
    }
    new_peer->next = *head; // Insertion en tête
    *head = new_peer;

    return 0;
}

