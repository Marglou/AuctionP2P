/*
 *   Des fonctions utilisées pour gérer un pair dans le système d'enchères distribué.
 *   Ce module permet à chaque pair de :
 *     - Participer à des enchères via multicast UDP.
 *     - Échanger des informations avec les autres pairs et le superviseur.
 *     - Gérer ses clés cryptographiques et sécuriser les échanges.
*/
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
#include "../include/udp_response.h"

//info superviseur 
int is_superviseur=0;
int enchere_supervise=0;
Peer p = {0}; // Structure pour stocker les informations du pair
volatile sig_atomic_t already_cleaned = 0;
volatile sig_atomic_t stop_threads = 0; // Variable pour arrêter les threads proprement

// Gestion de la déconnexion propre avec Ctrl+C
void handle_sigint(int sig) {
    // utiliser sig pour enlever les warnings
    (void)sig;
    stop_threads = 1; // Indiquer aux threads de s'arrêter
    already_cleaned = 1; // Indiquer que le nettoyage a déjà été effectué
    char leave_msg[BUF_SIZE];
    snprintf(leave_msg, sizeof(leave_msg), "[LEAVE] %s a quitté le groupe.\n", p.pseudo);

    if (send_multicast(p.adr_liaison.sock,leave_msg, strlen(leave_msg)) != 0) {
        fprintf(stderr, "Erreur lors de l'envoi du message de départ.\n");
    }

    if (p.enchere_active >= 0 && p.encheres[p.enchere_active].is_superviseur == 1) {
        uint8_t msg_16[7];
        if (msg_16_17(msg_16, 16, p.encheres[p.enchere_active].my_id, p.encheres[p.enchere_active].numv_supervise) != 7) {
            fprintf(stderr, "Erreur lors de la création du message de départ.\n");
        } else {
            if (send_msg_enchere(msg_16, sizeof(msg_16), p.enchere_active, p.encheres[p.enchere_active].sock) != 0) {
                fprintf(stderr, "Erreur lors de l'envoi du message de départ.\n");
            }
        }
    } else if (p.enchere_active >= 0) {
        uint8_t msg[3];
        if (msg_51(msg, p.encheres[p.enchere_active].my_id) != 3) {
            fprintf(stderr, "Erreur lors de la création du message de départ.\n");
        } else {
            if (send_msg_enchere(msg, sizeof(msg), p.enchere_active, p.encheres[p.enchere_active].sock) <= 0) {
                fprintf(stderr, "Erreur lors de l'envoi du message de départ.\n");
            }
        }
    }

    // if (is_superviseur) {
    //     cleanup_auction_supervisor(); // Clean up supervisor state if we were a supervisor
    // }

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

    p.id_peer = generer_id_peer();
    p.pseudo = strdup(nom);
    if (p.pseudo == NULL) {
        perror("Erreur d'allocation mémoire pour le p.pseudo");
        exit(EXIT_FAILURE);
    }

// -----------------------------     SECURITE  -------------------------------------------------------
    init_openssl();
    char ed_pub[256], ed_priv[256];
    snprintf(ed_pub, sizeof(ed_pub), "%s_ed_pubKey.pem", p.pseudo);
    snprintf(ed_priv, sizeof(ed_priv), "%s_ed_privKey.pem", p.pseudo);

    p.ed_pubkey_path = strdup(ed_pub);
    p.ed_privkey_path = strdup(ed_priv);

     // Générer et enregistrer les clés ED25519
    if (generate_ed25519_key(ed_pub, ed_priv)) {
        p.ed_privkey = convert_private_key_to_evp_pkey(ed_priv);
       p.ed_pubkey = convert_public_key_to_evp_pkey(ed_pub);

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

// -----------------------  Adresse perso IPv6 TCP/UDP ---------------------------------------------------------------

    char ip_str[INET6_ADDRSTRLEN];

    printf("Entrez le port perso (49152-65535) : ");
    if (scanf("%hu", &p.port_perso) != 1 || p.port_perso < 49152 || p.port_perso > 65535) {
        fprintf(stderr, "Port invalide. Le port doit être entre 49152 et 65535.\n");
        exit(EXIT_FAILURE);
    }

    printf("Entrez le montant initial du compte : ");
    if (scanf("%u", &p.compte) != 1) {
        fprintf(stderr, "Montant invalide.\n");
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
    
    p.adr_perso.sin6_family = AF_INET6;
    p.adr_perso.sin6_port = htons(p.port_perso); // Port personnel saisi par l'utilisateur

    if (inet_pton(AF_INET6, ip_str, &p.adr_perso.sin6_addr) != 1) {
        fprintf(stderr, "Erreur de conversion inet_pton\n");
        exit(EXIT_FAILURE);
    }

    if (IN6_IS_ADDR_LINKLOCAL(&p.adr_perso.sin6_addr)) {
        p.adr_perso.sin6_scope_id = p.global_iface_index; 
    }
    p.adr_perso.sin6_scope_id = p.global_iface_index;

    // Création sockets perso (TCP & UDP)
    if (create_perso_adr_sockets(p.adr_perso, p.global_iface_index, &p.socket_tcp, &p.socket_udp, p.port_perso) != 0) {
        printf("test:%d\n",p.global_iface_index);
        fprintf(stderr, "Erreur lors de la création des sockets perso TCP/UDP.\n");
        exit(EXIT_FAILURE);
    }

// ------------------------------- MULTICAST ---------------------------------------------------

    p.adr_liaison.sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (p.adr_liaison.sock < 0) {
        perror("socket multicast");
        free(p.pseudo);
        exit(EXIT_FAILURE);
    }

    p.adr_liaison.addr.sin6_family = AF_INET6;
    p.adr_liaison.addr.sin6_port = htons(PORT);
    p.adr_liaison.addr.sin6_addr = in6addr_any;  

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

    if (bind(p.adr_liaison.sock, (struct sockaddr *)&p.adr_liaison.addr, sizeof(p.adr_liaison.addr)) < 0) {
        perror("bind multicast");
        clean_peer();
        exit(EXIT_FAILURE);
    }

    if (inet_pton(AF_INET6, GROUP, &p.adr_liaison.mreq.ipv6mr_multiaddr) != 1) {
        perror("inet_pton multicast");
        clean_peer();
        exit(EXIT_FAILURE);
    }

    p.adr_liaison.mreq.ipv6mr_interface = p.global_iface_index;

    if (setsockopt(p.adr_liaison.sock, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                &p.adr_liaison.mreq, sizeof(p.adr_liaison.mreq)) < 0) {
        perror("setsockopt IPV6_JOIN_GROUP");
        clean_peer();
        exit(EXIT_FAILURE);
    }

    if (inet_pton(AF_INET6, GROUP, &p.adr_liaison.addr.sin6_addr) != 1) {
        perror("inet_pton multicast");
        clean_peer();
        exit(EXIT_FAILURE);
    }

    p.adr_liaison.addr.sin6_scope_id = p.global_iface_index;

    printf("Abonné au groupe multicast %s sur l'interface %d\n", GROUP, p.global_iface_index);

    signal(SIGINT, handle_sigint);

// --------------------------------------------------------------------------------
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
 
    if (pthread_create(&p.thread_tcp, NULL, listen_tcp_thread, &p.listener_tcp) != 0) {
        perror("Erreur lors de la création du thread TCP");
        clean_peer();
        exit(EXIT_FAILURE);
    }

    if (pthread_create(&p.thread_global, NULL, listen_main_sockets, NULL) != 0) {
        perror("Erreur lors de la création du thread principal");
        clean_peer();
        exit(EXIT_FAILURE);
    }

    init_udp_response_manager(&p.udp_responses); 
    if (pthread_mutex_init(&p.compte_mutex, NULL) != 0) {
        fprintf(stderr, "Erreur lors de l'initialisation du mutex du compte.\n");
        exit(EXIT_FAILURE);
    }

    pthread_join(p.thread_tcp, NULL);
    pthread_join(p.thread_global, NULL);
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

            uint8_t peekbuf[1];
            ssize_t peeklen = recv(client_sock, peekbuf, 1, MSG_PEEK);
            // ssize_t peeklen = SSL_peek(ssl, peekbuf, sizeof(peekbuf));
            if (peeklen <= 0) {
                close(client_sock);
                continue;
            }

            if (peekbuf[0] == 4) {
                uint8_t buffer[BUF_SIZE];
                ssize_t len = recv(client_sock, buffer, BUF_SIZE, 0);
                // ssize_t len = SSL_read(ssl, buffer, sizeof(buffer));
                if (len <= 0) {
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
                                char ip_str[INET6_ADDRSTRLEN];
                                inet_ntop(AF_INET6, &parsed_msg.ip, ip_str, sizeof(ip_str));
                                printf("Message 50 envoyé à %s:%u avec ID=%u\n",
                                ip_str, ntohs(parsed_msg.port),parsed_msg.id);
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
                        if (p.encheres[p.enchere_active].nb_pairs == 1){
                        } else {
                            connect_to_peers_and_send_info(p.encheres[p.enchere_active].liste_participants,parsed_msg.id,parsed_msg.ip,parsed_msg.port,parsed_msg.cle);
                        }
                        
                        if (add_peer(&p.encheres[p.enchere_active].liste_participants,parsed_msg.id, parsed_msg.ip,parsed_msg.port,parsed_msg.cle) == 0) {
                            // printf("Peer ajouté avec succès : ID=%d, Port=%d\n", parsed_msg.id, parsed_msg.port);
                            p.encheres[p.enchere_active].nb_pairs++;                       
                        } else {
                            supp_peer_list(&p.encheres[p.enchere_active].liste_participants,parsed_msg.id);
                            fprintf(stderr, "Erreur lors de l'ajout du pair à la liste des participants.\n");
                        }
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
             char ip_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &src.sin6_addr, ip_str, sizeof(ip_str));
            // printf("Message send a [%s]:%d\n", ip_str, ntohs(src.sin6_port));
        }
        return 0;
    } 

    // Traitement texte normal
    printf("[Multicast] %s\n", buf);
    fflush(stdout);

    // // Exemple de gestion de validation
    // if (strncmp(buf, "[VALIDATION]", 12) == 0) {
    //     char *msg = strchr(buf, ' ') + 1;
    //     char *sig_str = strchr(msg, ' ') + 1;
    //     unsigned char sig[256];
    //     size_t siglen = strlen(sig_str) / 2;
    //     for (size_t i = 0; i < siglen; i++) {
    //         sscanf(sig_str + 2 * i, "%2hhx", &sig[i]);
    //     }

    //     EVP_PKEY *peer_pubkey = get_peer_pubkey(p.pseudo);
    //     if (peer_pubkey && verify_message(peer_pubkey, (unsigned char *)msg, strlen(msg), sig, siglen)) {
    //         printf("Message validé par %s\n", p.pseudo);
    //     } else {
    //         printf("Échec de la vérification du message de %s\n", p.pseudo);
    //     }
    // }
    return 0;
}

int gestion_reception_UDP(int *nb) {

    uint8_t buf[1024];
    struct sockaddr_in6 src = {0};
    socklen_t len = sizeof(src);

    struct valid_peer *head = NULL;
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
    if (buf[0] == 4 && p.num_peers >= 0 && p.nb_encheres== 0) {
        (*nb) = -1;
        struct message_4 parsed_msg;
        if (parse_msg_4(buf, len, &parsed_msg) == 0) {
            p.discovered_peers[p.num_peers++] = (struct peer_info){
                .id = parsed_msg.id,
                .ip = parsed_msg.ip,
                .port_tcp = (parsed_msg.port)};
            p.listener_tcp.response_received = 1;
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
                //      close(socket_P);
                //      printf("Erreur connexion à Q\n");
                //      return -1;
                //  }

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
            
                for (int i = 0; i < p.encheres[p.nb_encheres].nb_pairs; i++) {
                    if (recevoir_infos_peer(socket_P, &p.encheres[p.nb_encheres]) != 0) {
                        fprintf(stderr, "Erreur lors de l'ajout du pair à la liste.\n");
                        close(socket_P);
                        return -1;
                    }
                }

                int enchere_precedente = p.enchere_active; // Enchère précédente
                p.enchere_active = p.nb_encheres; // Indique que nous avons rejoint l'enchère active
                // printf("enchere active %d    nb enchere %d\n", p.enchere_active, p.nb_encheres);
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

                printf("\n");
                if (join_enchere(p.encheres[p.enchere_active].id_enchere, 
                                str_ip, p.encheres[p.enchere_active].port_enchere) != 0) {
                    fprintf(stderr, "Erreur lors de la jointure de l'enchère.\n");
                    memset(&p.encheres[p.enchere_active], 0, sizeof(EnchereSocket));
                    p.enchere_active = enchere_precedente; // Reset active auction
                    send(socket_P, "erreur", 6, 0);
                    // SSL_write(socket_P, "erreur", 6);
                    close(socket_P);
                    // cleanup_ssl_connection(ssl);
                    return -1;
                }
             
                p.num_peers = 0;
                memset(&p.discovered_peers, 0, sizeof(p.discovered_peers));
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
        struct message_1 parsed_msg = {0};
        int msg_len = sizeof(parsed_msg);
        int erreur = parse_msg_1(buf, msg_len, &parsed_msg);
        if (erreur == 0) {
            printf("Message 1 reçu : ID=%u, MESS=%s \n", parsed_msg.id, parsed_msg.mess);

            mark_response_received(&p.udp_responses, 1, parsed_msg.id);
            add_valid_peer(&head, parsed_msg.id, parsed_msg.lsig, parsed_msg.sig);
            p.encheres[p.enchere_active].nb_msg_1 += 1;
        }

        if (strcmp(parsed_msg.mess, "superviseur") == 0) {
           
            if (parsed_msg.id > p.encheres[p.enchere_active].my_id) {
                printf("Je suis peut être superviseur\n");
            } else {
                printf("Je ne suis pas le superviseur\n");
                pthread_mutex_lock(&p.encheres[p.enchere_active].superviseur_mutex);
                printf("superviseur %d\n", p.encheres[p.enchere_active].superviseur_actif);
                p.encheres[p.enchere_active].superviseur_actif = 0;
                printf("superviseur %d\n", p.encheres[p.enchere_active].superviseur_actif);
                pthread_cond_signal(&p.encheres[p.enchere_active].superviseur_cond);  
                pthread_mutex_unlock(&p.encheres[p.enchere_active].superviseur_mutex);
                return 0;
            }
        }

        if (p.encheres[p.enchere_active].nb_msg_1 == p.encheres[p.enchere_active].nb_pairs-1) { 
            
            if (p.encheres[p.enchere_active].nb_msg_1 <= 3) {

                uint8_t msg[BUF_SIZE];
                unsigned char *signature = NULL;
                size_t siglen = 0;

                if (!sign(p.ed_privkey, (unsigned char *) parsed_msg.mess, &signature, &siglen)) {
                    fprintf(stderr, "Erreur lors de la signature\n");
                    return -1;
                }

                uint16_t peer_ids[3];
                uint8_t sig_lengths[3];
                unsigned char *signatures[3];
                struct valid_peer *cur = head;
                int idx = 0;
                while (cur && idx < p.encheres[p.enchere_active].nb_msg_1) {
                    peer_ids[idx] = cur->id;
                    sig_lengths[idx] = cur->lsig;
                    signatures[idx] = cur->sig;
                    idx++;
                    cur = cur->next;
                }

                int msg2_len = msg_2(msg, p.id_peer, parsed_msg.mess, signature, siglen,
                                    p.encheres[p.enchere_active].nb_msg_1, peer_ids, sig_lengths, signatures);
                free(signature);

                if (msg2_len < 0) {
                    fprintf(stderr, "Erreur lors de la construction du message 2.\n");
                    free_valid_peer_list(head);
                    return -1;
                }
                free_valid_peer_list(head);

                if (send_msg_enchere(msg, msg2_len, p.enchere_active, p.encheres[p.enchere_active].sock) < 0) {
                    perror("sendto dans gestion reception UDP MSG 2");
                    p.encheres[p.enchere_active].nb_msg_1 = 0;
                    return -1;
                } else {
                    p.encheres[p.enchere_active].nb_msg_1 = 0;
                }
                p.encheres[p.enchere_active].consensus = 0;
            
                if (strncmp(parsed_msg.mess, "vente:", 6) == 0) {
                    int numv = 0;
                    uint32_t prix = 0;
                    // On attend "vente:numv:prix"
                    if (sscanf(parsed_msg.mess + 6, "%d:%u", &numv, &prix) == 2) {
                        printf("Vente validée, numéro de vente : %d, nouveau prix : %u\n", numv, prix);
                        update_vente(&p.encheres[p.enchere_active], numv, prix);
                    } else {
                        printf("Erreur lors du parsing du numéro de vente et du prix\n");
                    }
                }
                //si quitte enchere reinit parametre
                else if(strcmp(parsed_msg.mess,"quitter")==0){
                    printf("quitter enchere\n");
                    clean_encheres(p.encheres[p.enchere_active].id_enchere);
                    p.enchere_active = -1;//Attention risque de probleme, on suppose qu'il n'y avait qu'une enchere active 
                    is_superviseur = 0;
                } else if (strcmp(parsed_msg.mess, "superviseur") != 0) {
                    // Envoi du message 3
                    uint8_t msg_17[7];
                    if (msg_16_17(msg_17, 17, p.encheres[p.enchere_active].my_id, p.encheres[p.enchere_active].numv_supervise) != 7) {
                        fprintf(stderr, "Erreur lors de la construction du message 17.\n");
                        return -1;
                    }
                    if (send_msg_enchere(msg_17, sizeof(msg_17), p.enchere_active, p.encheres[p.enchere_active].sock) < 0) {
                        perror("send_msg_enchere");
                        return -1;
                    } else {
                        printf("Message 17 envoyé à l'enchère active.\n");
                    }
                }
            } 
        }
        return 0;
    } 
    printf("[Unicast UDP] %s\n", buf);
    fflush(stdout);
    check_and_retry_messages(&p.udp_responses);
    return 0;
}

// int gestion_reception_TCP(int client_fd, struct tcp_listener_state* listener) {
//     printf("Gestion de la réception TCP...\n");
//     struct sockaddr_in6 client_addr = {0};
//     socklen_t addr_len = sizeof(client_addr);

//     uint8_t peekbuf[1];
//     ssize_t peeklen = recv(client_fd, peekbuf, 1, MSG_PEEK);
//     if (peeklen <= 0) {
//         close(client_fd);
//         perror("recv");
//         return -1;
//     }
//     else if (peekbuf[0] == 5) {
//         // Message 5
//         uint8_t buffer[BUF_SIZE];
//         ssize_t len = recv(client_fd, buffer, BUF_SIZE, 0);
//         if (len > 0 && buffer[0] == 5)
//         {
//             struct message_5 parsed_msg;
//             if (parse_msg_5(buffer, len, &parsed_msg) == 0)
//             {
//                 printf("Message 5 reçu : ID=%u, PORT=%u\n", parsed_msg.id, ntohs(parsed_msg.port));
//                 listener->response_received = true;
//                 listener->first_response_time = time(NULL);

//                 bool id_exists = false;
//                 int count = 0, position_enr = 0;
//                 for (int i = 0; i < p.num_peers; ++i)
//                 {
//                     if (p.discovered_peers[i].id == parsed_msg.id)
//                         count++;
//                     if (count == 2)
//                     {
//                         id_exists = true;
//                         position_enr = i;
//                         break;
//                     }
//                 }

//                 if (!id_exists && p.num_peers < MAX_PEERS)
//                 {
//                     uint8_t msg[1];
//                     int msg_len = msg_50(msg);
//                     if (send(client_fd, msg, msg_len, 0) != msg_len)
//                         perror("send msg_50");
//                     else
//                         printf("Message 50 envoyé à %s:%u avec ID=%u\n",
//                                 inet_ntoa(*(struct in_addr *)&parsed_msg.ip),
//                                 ntohs(parsed_msg.port), parsed_msg.id);
//                 }
//                 else {
//                     uint16_t new_id = rand() % 25;
//                     uint8_t msg[3];
//                     int msg_len = msg_51(msg, new_id);
//                     if (send(client_fd, msg, msg_len, 0) != msg_len) {
//                         perror("send msg_51");
//                     } else {
//                         printf("Message 51 envoyé à %s:%u avec nouvel ID=%u\n",
//                                 inet_ntoa(*(struct in_addr *)&parsed_msg.ip),
//                                 ntohs(parsed_msg.port), new_id);
//                         p.discovered_peers[position_enr].id = new_id;
//                     }
//                 }

//                 // Envoi du message 7
//                 uint8_t msg7_buf[BUF_SIZE];
//                 int taille = message_7_header(msg7_buf, sizeof(msg7_buf), p.encheres[0]);
//                 size_t total_sent = 0;
//                 while (total_sent < taille)
//                 {
//                     ssize_t sent = send(client_fd, msg7_buf + total_sent, taille - total_sent, 0);
//                     if (sent < 0)
//                     {
//                         perror("Erreur d'envoi du message");
//                         close(client_fd);
//                         return -1;
//                     }
//                     total_sent += sent;
//                 }

//                 printf("Message 7 header envoyé (%zu octets).\n", total_sent);
//                 print_peer_list(p.encheres[0].liste_participants);
//                 envoyer_infos_peers(client_fd, &p.encheres[0]);
//                 close(client_fd);
//                 return 0;
//             }
//         }
//     } else {
//         // Autres messages
//         char buffer[BUF_SIZE];
//         ssize_t len = recv(client_fd, buffer, sizeof(buffer), 0);
//         if (len > 0) {
//             buffer[len] = '\0';
//             printf("[TCP] %s\n", buffer);
//             fflush(stdout);
//         }
//     }
//     close(client_fd);
//     return 0;
// }


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

    int nb_msg_3 = -1;
    time_t join_start = time(NULL);

    while (1) {
        int ret = poll(fds, n, 5000);  

        if (ret < 0) {
            perror("poll");
            break;
        }

        if (nb_msg_3 > 0) {
            if (join_start == 0) join_start = time(NULL);

            // Si on a attendu plus de 3 secondes sans réponse
            if (time(NULL) - join_start > 3) {
                nb_msg_3++;
                if (nb_msg_3 > 4) {
                    printf("Aucune réponse après 3 tentatives. Abandon.\n");
                    nb_msg_3 = -1;
                    join_start = 0;
                    creer_enchere();
                } else {
                    printf("Relance tentative join (%d/3)\n", nb_msg_3);
                    msg_join_enchere(); // renvoie le message 3
                    join_start = time(NULL);
                }
            }
        }

        // SOCKET MULTICAST
        if (fds[0].revents & POLLIN) {
            if (gestion_reception_liaison() < 0) {
                fprintf(stderr, "Erreur lors de la réception du message multicast.\n");
            }
        }

        // SOCKET UNICAST UDP
        if (fds[1].revents & POLLIN) {
            if (gestion_reception_UDP(&nb_msg_3) < 0) {
                fprintf(stderr, "Erreur lors de la réception du message unicast.\n");
            }
        }

        // ENTRÉE CLAVIER
        if (fds[2].revents & POLLIN) {
            char input[BUF_SIZE];
            if (fgets(input, sizeof(input), stdin) != NULL) {
                size_t len = strlen(input);
                if (len > 0 && input[len - 1] == '\n') {
                    input[len - 1] = '\0'; 
                }

                if (strcmp(input, "lancer") == 0) {
                    stop_threads = 0;
                    p.nb_encheres = 0;
                    p.enchere_active = -1;
                    creer_enchere();
                    p.encheres[p.enchere_active].my_id = p.id_peer;
                    continue;
                }
                else if (strcmp(input, "join") == 0) {
                    nb_msg_3 = 1; 
                    join_start = 0; 
                    if (nb_msg_3 > 0) {
                        if (msg_join_enchere() == -1) {
                            printf("Erreur lors de l'envoi de la demande de rejoindre l'enchère.\n");
                        }
                        nb_msg_3++;
                    }
                    continue;
                }
                // else if (strncmp(input, "offre ", 6) == 0) {
                //     uint32_t prix;
                //     if (sscanf(input + 6, "%u", &prix) == 1) {
                //         faire_offre(prix);
                //     } else {
                //         printf("Format invalide. Utilisez: offre <prix>\n");
                //     }
                //     continue;
                // }
                else if (strncmp(input, "help", 4) == 0) {
                    printf("Commandes disponibles:\n");
                    printf(" - lancer : Lancer une enchère\n");
                    printf(" - join : Rejoindre une enchère\n");
                    printf(" - offre <prix> : Faire une offre\n");
                    printf(" - encheres : Afficher les enchères avec vente\n");
                    printf(" - vente : Initier une vente\n");
                    printf(" - offre : Surencherir\n");
                    printf(" - solede : Affiche le compte \n");
                    printf(" - quit : Quitter le programme\n");
                    continue;
                }
                else if (strcmp(input, "quit") == 0) {
                    if(p.enchere_active >= 0 && p.encheres[p.enchere_active].sock>0 && p.encheres[p.enchere_active].nb_pairs > 1){
                        mettre_fin();
                        continue;
                    } else if ( p.enchere_active >= 0 && p.encheres[p.enchere_active].nb_pairs == 1){
                        if (clean_encheres(p.encheres[p.enchere_active].id_enchere) != 0 ){
                            printf("Erreur qd on veut partir\n");
                            clean_peer();
                        }
                        printf("je suis partieeeeee\n");
                        p.enchere_active = -1;
                        is_superviseur = 0;
                        continue;
                    }
                    
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
                    if (p.encheres[p.enchere_active].is_superviseur == 1){
                        printf("Deja superviseur d'une vente\n");
                        continue;
                    }
                    if (p.encheres[p.enchere_active].nb_pairs <= 1) {
                        printf("Attendre d'être au moins deux\n");
                        continue;
                    }
                    if (init_vente() == -1) {
                        printf("Erreur lors de l'initiation de la vente.\n");
                    }
                    printf("Vente initiée.\n");
                    continue;
                } 
                else if (strcmp(input, "offre") == 0) {
                    if (p.encheres[p.enchere_active].nb_ventes == 0) {
                        printf("Initier une vente auparavent\n");
                        continue;
                    }
                    if (sur_enchere() == -1) {
                        printf("Erreur lors de la surenchère.\n");
                    }
                    printf("Surenchère effectuée.\n");
                    continue;
                }
                else if (strncmp(input, "switch ", 7) == 0) {
                    int idx = atoi(input + 7);
                    if (idx >= 0 && idx < p.nb_encheres) {
                        afficher_enncheres();
                        p.enchere_active = idx;
                        printf("Enchère active changée : %d (ID=%d)\n", idx, p.encheres[idx].id_enchere);
                    } else {
                        printf("Indice d'enchère invalide.\n");
                    }
                    continue;
                }
                else if (strcmp(input, "solede") == 0) {
                    printf("Solde actuel : %d\n", lire_compte());
                    continue;
                }
                else {
                    if (strlen(input) == 0) {
                        continue; 
                    }

                    char message[BUF_SIZE];
                    snprintf(message, sizeof(message), "[%s] %s", p.pseudo, input);

                    if (p.enchere_active >= 0) {
                        if (send_msg_enchere((uint8_t *) message, strlen(message), p.enchere_active, p.encheres[p.enchere_active].sock) < 0) {
                            fprintf(stderr, "Erreur lors de l'envoi du message d'enchère\n");
                        }
                    } else {
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

int supp_peer_list(peer_list **h, int id) {
    if (h == NULL || *h == NULL) {
        printf("Liste vide, rien à supprimer.\n");
        return -1;
    }

    peer_list *curr = *h;
    peer_list *prev = NULL;

    print_peer_list(*h);

    while (curr != NULL) {
        if (curr->id == id) {
            if (prev == NULL) {
                // Suppression du premier (tête de liste)
                *h = curr->next;
                printf("Suppression en tête : ID=%d\n", id);
            } else {
                // Suppression au milieu ou à la fin
                prev->next = curr->next;
                printf("Suppression d'un pair interne : ID=%d\n", id);
            }
            free(curr);
            return 0;
        }
        prev = curr;
        curr = curr->next;
    }
    print_peer_list(*h);
    printf("ID %d non trouvé dans la liste.\n", id);
    return -1;
}

void clean_peer() {

    for (int i = 0; i < p.nb_encheres; i++) {
        if (p.encheres[i].sock >= 0) {
            struct ipv6_mreq mreq;
            memset(&mreq, 0, sizeof(mreq));
            memcpy(&mreq.ipv6mr_multiaddr, &p.encheres[i].group, sizeof(struct in6_addr));
            mreq.ipv6mr_interface = p.global_iface_index;

            if (setsockopt(p.encheres[i].sock, IPPROTO_IPV6, IPV6_LEAVE_GROUP, &mreq, sizeof(mreq)) < 0) {
                perror("setsockopt IPV6_LEAVE_GROUP");
            }

            free_peer_list(p.encheres[i].liste_participants);  
            p.encheres[i].liste_participants = NULL;
            pthread_cancel(p.encheres[i].thread_id); 
            pthread_join(p.encheres[i].thread_id, NULL); 

            pthread_mutex_destroy(&p.encheres[i].superviseur_mutex);
            pthread_cond_destroy(&p.encheres[i].superviseur_cond);
            close(p.encheres[i].sock);
            p.encheres[i].sock = -1;
        }
    }

    pthread_cancel(p.thread_tcp);
    pthread_cancel(p.thread_global);

    pthread_join(p.thread_tcp, NULL);
    pthread_join(p.thread_global, NULL);

    if (p.socket_tcp >= 0) {
        close(p.socket_tcp);
        p.socket_tcp = -1;
    }

    if (p.socket_udp >= 0) {
        close(p.socket_udp);
        p.socket_udp = -1;
    }

    if (p.adr_liaison.sock >= 0) {
        setsockopt(p.adr_liaison.sock, IPPROTO_IPV6, IPV6_LEAVE_GROUP,
                   &p.adr_liaison.mreq, sizeof(p.adr_liaison.mreq));
        close(p.adr_liaison.sock);
        p.adr_liaison.sock = -1;
    }

    if (p.ed_privkey) EVP_PKEY_free(p.ed_privkey);
    if (p.ed_pubkey) EVP_PKEY_free(p.ed_pubkey);
    SSL_CTX_free(p.ctx);
    
    if (p.pseudo) {
        free(p.pseudo);
        p.pseudo = NULL;
    }

    if (p.cert_path) {
        free(p.cert_path);
        p.cert_path = NULL;
    }

    if (p.ed_privkey_path) {
        free(p.ed_privkey_path);
        p.ed_privkey_path = NULL;
    }

    if (p.ed_pubkey_path) {
        free(p.ed_pubkey_path);
        p.ed_pubkey_path = NULL;
    }

    cleanup_udp_response_manager(&p.udp_responses);
    pthread_mutex_destroy(&p.compte_mutex);
    printf("Vous partez avec un montant de %d euros.\n", p.compte);
    
}

// Function to connect to all other peers and send message 6
int connect_to_peers_and_send_info(peer_list *h, uint16_t new_peer_id, struct in6_addr new_peer_ip, 
                                  uint16_t new_peer_port, unsigned char *new_peer_cle) {
     int ret = 0;
    peer_list *current = h;

    
    while (current != NULL) {
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &new_peer_ip, ip_str, sizeof(ip_str));
        // printf("info peer id %d, port %d\n", current->id, current->port_tcp);
        // printf("info peer ip %s\n", ip_str, NULL, 0);
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


int add_peer(peer_list **head, uint16_t id, struct in6_addr ip, uint16_t port, unsigned char *cle) {

    if (id < 0 ) {
        fprintf(stderr, "ID invalide : %d\n", id);
        return -1;
    }

    if (port < 0 || port > 65535) {
        fprintf(stderr, "Port invalide : %d\n", port);
        return -1;
    }

    char ip_str[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, &ip, ip_str, sizeof(ip_str)) == NULL) {
        perror("inet_ntop");
        return -1;
    }

    peer_list *new_peer = malloc(sizeof(peer_list));
    if (!new_peer) {
        perror("Erreur d'allocation mémoire pour le peer");
        return -1;
    }

    new_peer->id = id;
    new_peer->ip = ip;

    printf("Ajout peer IP %s\n", ip_str);

    new_peer->port_tcp = port;

    if (cle != NULL) {
        memcpy(new_peer->cle, cle, 113);
    } else {
        memset(new_peer->cle, 0, 113);
    }

    new_peer->next = *head;
    *head = new_peer;

    return 0;
}


void incrementer_compte(int montant) {
    pthread_mutex_lock(&p.compte_mutex);
    p.compte += montant;
    pthread_mutex_unlock(&p.compte_mutex);
}

int decrementer_compte(int montant) {
    pthread_mutex_lock(&p.compte_mutex);
    if (p.compte < montant) {
        pthread_mutex_unlock(&p.compte_mutex);
        printf("Fonds insuffisants.\n");
        return -1;
    }
    p.compte -= montant;
    pthread_mutex_unlock(&p.compte_mutex);
    return 0;
}

int lire_compte() {
    pthread_mutex_lock(&p.compte_mutex);
    uint32_t val = p.compte;
    pthread_mutex_unlock(&p.compte_mutex);
    return val;
}