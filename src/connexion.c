// connexion.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/socket.h>
// #include <asm-generic/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <net/if.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "../include/connexion.h"
#include "../include/peer.h"
#include "../include/superviseur.h"
#include "../include/message.h"
#include "../include/enchere.h"
#include "../include/utils.h"

int connexion_TLS(struct in6_addr ip, uint16_t port) {
    char ip_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip, ip_str, sizeof(ip_str));
    printf("Connexion TLS à %s:%u...\n", ip_str, (port));    

    // // Initialize SSL context
    // SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    // if (!ctx) {
    //     ERR_print_errors_fp(stderr);
    //     return -1;
    // }


    //     // Charger le certificat
    //     char cert_path[256], key_path[256];
    //     snprintf(cert_path, sizeof(cert_path), "certs/%s/cert.pem", pseudo);
    //     snprintf(key_path, sizeof(key_path), "certs/%s/key.pem", pseudo);
        
    //     if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0) {
    //         fprintf(stderr, "Erreur lors du chargement du certificat depuis %s\n", cert_path);
    //         ERR_print_errors_fp(stderr);
    //         return -1;
    //     }
        
    //     if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
    //         fprintf(stderr, "Erreur lors du chargement de la clé privée depuis %s\n", key_path);
    //         ERR_print_errors_fp(stderr);
    //         return -1;
    //     }
        

    // // Vérifie que la clé privée correspond au certificat
    // if (!SSL_CTX_check_private_key(ctx)) {
    //     fprintf(stderr, "Erreur : la clé privée ne correspond pas au certificat public\n");
    //     return NULL;
    // }



    // // Create SSL structure
    // SSL *ssl = SSL_new(ctx);
    // if (!ssl) {
    //     ERR_print_errors_fp(stderr);
    //     SSL_CTX_free(ctx);
    //     return -1;
    // }

    // Create socket
    int socket_tcp_client = socket(AF_INET6, SOCK_STREAM, 0);
    if (socket_tcp_client < 0) {
        perror("socket TCP");
        // SSL_free(ssl);
        // SSL_CTX_free(ctx);
        return -1;
    }

    // Set socket options
    struct timeval tv;
    tv.tv_sec = 5;  // 5 seconds timeout
    tv.tv_usec = 0;
    setsockopt(socket_tcp_client, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(socket_tcp_client, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    // Set up connection address
    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(port);  // Port is already in network byte order
    dest.sin6_addr = ip;
    if (IN6_IS_ADDR_LINKLOCAL(&ip)) {
        dest.sin6_scope_id = global_iface_index;
    }

    // Connect
    if (connect(socket_tcp_client, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("connect");
        // SSL_free(ssl);
        // SSL_CTX_free(ctx);
        close(socket_tcp_client);
        return -1;
    }

    // Associate socket with SSL structure
    // SSL_set_fd(ssl, socket_tcp_client);

    // // Perform SSL handshake
    // if (SSL_connect(ssl) <= 0) {
    //     ERR_print_errors_fp(stderr);
    //     SSL_free(ssl);
    //     SSL_CTX_free(ctx);
    //     close(socket_tcp_client);
    //     return -1;
    // } 


    // printf("SSL connection established\n");

    // Send message 5
    uint8_t msg[1 + 2 + 16 + 2 + 113];  // CODE + ID + IP + PORT + CLE
    unsigned char CLE[113];
    // if (format_ed25519_public_key(cle, my_pubkey) != 0) {
    //     printf("Erreur lors du formatage de la clé publique.\n");
    //     // SSL_free(ssl);
    //     // SSL_CTX_free(ctx);
    //     close(socket_tcp_client);
    //     return -1;
    // }

    if (generate_ed25519_keypair_and_extract_CLE("key.pem", CLE) == 0) {
        // printf("CLE (113 octets) :\n%s\n", CLE);
    }

    uint16_t peer_id = (uint16_t)id_peer;

    if (msg_5(msg, peer_id, port_perso, CLE) != 134) {
        printf("Erreur lors de la construction du message.\n");
        // SSL_free(ssl);
        // SSL_CTX_free(ctx);
        close(socket_tcp_client);
        return -1;
    }

    // Send message
    if (send(socket_tcp_client, msg, sizeof(msg), 0) != sizeof(msg)) {
        perror("send");
        // SSL_free(ssl);
        // SSL_CTX_free(ctx);
        close(socket_tcp_client);
        return -1;
    }

    // if (SSL_write(ssl, msg, sizeof(msg)) <= 0) {
    //     ERR_print_errors_fp(stderr);
    //     SSL_free(ssl);
    //     SSL_CTX_free(ctx);
    //     close(socket_tcp_client);
    //     return -1;
    // }

    printf("Message 5 envoyé : ID=%d, IP=%s, PORT=%u\n", id_peer, ip_str, ntohs(port));

    // Wait for response (message 50 or 51)
    uint8_t response[3];
    ssize_t bytes_read = recv(socket_tcp_client, response, sizeof(response), 0);
    // int bytes_read = SSL_read(ssl, response, sizeof(response));
    if (bytes_read <= 0) {
        ERR_print_errors_fp(stderr);
        // SSL_free(ssl);
        // SSL_CTX_free(ctx);
        close(socket_tcp_client);
        return -1;
    }

    if (response[0] == 50) {
        // Received message 50 - ID already taken, get new ID
        struct message_50 msg_50;
        if (parse_msg_50(response, bytes_read, &msg_50) == 0) {
            printf("ID accepté \n");
            //snprintf(id_peer, sizeof(id_peer), "%u", msg_50.id);
        }
    } else if (response[0] == 51) {
        // Received message 51 - ID accepted
        struct message_51 msg_51;
        if (parse_msg_51(response, bytes_read, &msg_51) == 0) {
            printf("nouveau ID : %u\n", msg_51.id);
        }
    } else {
        printf("Message de réponse inattendu : %u\n", response[0]);
        // SSL_free(ssl);
        // SSL_CTX_free(ctx);
        close(socket_tcp_client);
        return -1;
    }

    // Keep SSL and socket for future use
    return socket_tcp_client;
}
