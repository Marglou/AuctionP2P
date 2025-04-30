// connexion.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <asm-generic/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <net/if.h>

#include "../include/connexion.h"
#include "../include/peer.h"
#include "../include/superviseur.h"
#include "../include/message.h"
#include "../include/enchere.h"


void *listen_tcp_thread(void *arg) {
    struct tcp_listener_state *state = arg;

    while (1) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(state->socket_tcp, &readfds);
        struct timeval timeout = { .tv_sec = 1, .tv_usec = 0 };

        if (select(state->socket_tcp + 1, &readfds, NULL, NULL, &timeout) > 0) {
            struct sockaddr_in6 client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int client_sock = accept(state->socket_tcp, (struct sockaddr *)&client_addr, &addr_len);
            if (client_sock < 0) {
                perror("accept");
                continue;
            }

            uint8_t buffer[BUF_SIZE];
            ssize_t len = recv(client_sock, buffer, BUF_SIZE, 0);
            if (len > 0 && buffer[0] == 4 && num_peers >= 0) {
                struct message_4 parsed_msg;
                if (parse_msg_4(buffer, len, &parsed_msg) == 0) {
                    printf("Pair trouvé : ID=%u, port=%u\n", parsed_msg.id, ntohs(parsed_msg.port));
                    discovered_peers[num_peers++] = (struct peer_info){
                        .id = parsed_msg.id,
                        .ip = parsed_msg.ip,
                        .port_tcp = parsed_msg.port
                    };
                    state->response_received = true;
                    state->first_response_time = time(NULL);
                }
            }

            close(client_sock);
        }
    }

    return NULL;
}

int connexion_TLS(struct in6_addr ip, uint16_t port) {
    char ip_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip, ip_str, sizeof(ip_str));
    printf("Connexion TLS à %s:%u...\n", ip_str, port);    
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    printf("SSL_CTX_new\n");
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        return -1;
    }

    int socket_tcp_client = socket(AF_INET6, SOCK_STREAM, 0);
    if (socket_tcp_client < 0) {
        perror("socket TCP");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return -1;
    }

    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(port);
    dest.sin6_addr = ip;
    if (IN6_IS_ADDR_LINKLOCAL(&ip)) {
        dest.sin6_scope_id = global_iface_index;
    }

    if (connect(socket_tcp_client, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("connect");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(socket_tcp_client);
        return -1;
    }

    SSL_set_fd(ssl, socket_tcp_client);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(socket_tcp_client);
        return -1;
    }

    uint8_t msg[21 + crypto_sign_PUBLICKEYBYTES];
    if (msg_5(msg, id_peer, port_tcp, my_pubkey) != 0) {
        printf("Erreur lors de la construction du message.\n");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(socket_tcp_client);
        return -1;
    }

    SSL_write(ssl, msg, sizeof(msg));

    char ip_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip, ip_str, sizeof(ip_str));
    printf("Message 5 envoyé : ID=%u, IP=%s, PORT=%u\n", id_peer, ip_str, port);

    close(socket_tcp_client);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}
