// connexion.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <net/if.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "../include/connexion.h"
#include "../include/peer.h"
#include "../include/message.h"
#include "../include/enchere.h"
#include "../include/utils.h"
#include "../include/securite.h"

int connexion_TCP (struct in6_addr ip, uint16_t port){
    char ip_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip, ip_str, sizeof(ip_str));
    printf("Connexion TCP à %s:%u...\n", ip_str, (port)); 

    // Create socket
    int socket_tcp_client = socket(PF_INET6, SOCK_STREAM, 0);
    if (socket_tcp_client < 0) {
        perror("socket TCP");
        return -1;
    }

    // Set socket options
    struct timeval tv;
    tv.tv_sec = 2;  // 5 seconds timeout
    tv.tv_usec = 0;
    setsockopt(socket_tcp_client, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(socket_tcp_client, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    // Set up connection address
    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(port);  // Port is already in network byte order
    dest.sin6_addr = ip;

    if (IN6_IS_ADDR_LINKLOCAL(&ip)) {
        dest.sin6_scope_id = p.global_iface_index;
    }
    dest.sin6_scope_id = p.global_iface_index;

    // Connect
    if (connect(socket_tcp_client, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("connect");
        close(socket_tcp_client);
        return -1;
    }
    
    return socket_tcp_client;
}

int connexion_TLS (struct in6_addr ip, uint16_t port) {
    
// SSL *connexion_TLS(struct in6_addr ip, uint16_t port) {
    char ip_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip, ip_str, sizeof(ip_str));
    printf("Connexion TLS à %s:%u...\n", ip_str, (port));    

    // Create socket
    int socket_tcp_client = socket(AF_INET6, SOCK_STREAM, 0);
    if (socket_tcp_client < 0) {
        perror("socket TCP");
        // SSL_free(ssl);
        return -1;
        // return NULL;
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
        dest.sin6_scope_id = p.global_iface_index;
    }
    dest.sin6_scope_id = p.global_iface_index;

    // // Connect
    if (connect(socket_tcp_client, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("connect");
        close(socket_tcp_client);
        return -1;
        // return NULL;
    }

    // // Create SSL structure
    // SSL *ssl = SSL_new(p.ctx);
    // if (!ssl) {
    //     ERR_print_errors_fp(stderr);
    //     // return -1;
    //     close(socket_tcp_client);
    //     return NULL;
    // }
    
    // // Associate socket with SSL structure
    // SSL_set_fd(ssl, socket_tcp_client);

    // printf("SSL avant connect\n");
    // // // Perform SSL handshake
    // if (SSL_connect(ssl) <= 0) {
    //     ERR_print_errors_fp(stderr);
    //     // SSL_CTX_free(ctx);
    //     SSL_shutdown(ssl);
    //     close(socket_tcp_client);
    //     SSL_free(ssl);
    //     // return -1;
    //     return NULL;
    // } 


    printf("SSL connection established\n");

    // Send message 5
    uint8_t msg[1 + 2 + 16 + 2 + 113];  // CODE + ID + IP + PORT + CLE
    unsigned char CLE[113];
    if (lire_cle_publique_pem(p.ed_pubkey_path, CLE) != 0) {
        fprintf(stderr, "Erreur lors de la lecture de la clé publique\n");
    }

    printf("cle : %s\n", CLE);

    // if (generate_ed25519_keypair_and_extract_CLE("key.pem", CLE) == 0) {
    //     // printf("CLE (113 octets) :\n%s\n", CLE);
    // }

    uint16_t peer_id = (uint16_t)p.id_peer;

    if (msg_5(msg, peer_id, p.port_perso, p.adr_perso.sin6_addr, CLE) != 134) {
        printf("Erreur lors de la construction du message.\n");
        // SSL_CTX_free(ctx);
        // cleanup_ssl_connection(ssl);
        close(socket_tcp_client);
        return -1;
        // return NULL;
    }

    // Send message
    if (send(socket_tcp_client, msg, sizeof(msg), 0) != sizeof(msg)) {
    // if (SSL_write(ssl, msg, sizeof(msg)) <= 0) {
        // ERR_print_errors_fp(stderr);
        perror("send");
        // cleanup_ssl_connection(ssl);
        close(socket_tcp_client);
        // SSL_CTX_free(ctx);
        return -1;
        // return NULL;
    }

    printf("Message 5 envoyé : ID=%d, IP=%s, PORT=%u\n", p.id_peer, ip_str, ntohs(port));

    // Wait for response (message 50 or 51)
    uint8_t response[3];
    ssize_t bytes_read = recv(socket_tcp_client, response, sizeof(response), 0);
    // int bytes_read = SSL_read(ssl, response, sizeof(response));
    if (bytes_read <= 0) {
        // ERR_print_errors_fp(stderr);
        // cleanup_ssl_connection(ssl);
        close(socket_tcp_client);
        return -1;
        // return NULL;
    }

    if (response[0] == 50) {
        
        struct message_50 msg_50;
        if (parse_msg_50(response, bytes_read, &msg_50) == 0) {
            printf("ID accepté   enchere active %d\n", p.enchere_active);

            p.encheres[p.nb_encheres].my_id = p.id_peer;
            printf("MY ID %d\n", p.encheres[p.nb_encheres].my_id);
            //snprintf(id_peer, sizeof(id_peer), "%u", msg_50.id);
        }
    } else if (response[0] == 51) {
        
        struct message_51 msg_51;
        if (parse_msg_51(response, bytes_read, &msg_51) == 0) {
            printf("nouveau ID : %u\n", msg_51.id);
            p.encheres[p.nb_encheres].my_id = msg_51.id;
        }
    } else {
        printf("Message de réponse inattendu : %u\n", response[0]);
        // cleanup_ssl_connection(ssl);
        close(socket_tcp_client);
        return -1;
        // return NULL;
    }

    // Keep SSL and socket for future use
    return socket_tcp_client;
    // return ssl;
}

