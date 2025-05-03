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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
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

            if (FD_ISSET(state->socket_tcp, &readfds)) {
                    // Accept incoming connection
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

    // Send message 5
    uint8_t msg[1 + 2 + 16 + 2 + 113];  // CODE + ID + IP + PORT + CLE
    unsigned char cle[113];
    if (format_ed25519_public_key(cle, my_pubkey) != 0) {
        printf("Erreur lors du formatage de la clé publique.\n");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(socket_tcp_client);
        return -1;
    }

    uint16_t peer_id = atoi(id_peer);
    if (msg_5(msg, peer_id, port_tcp, cle) != 0) {
        printf("Erreur lors de la construction du message.\n");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(socket_tcp_client);
        return -1;
    }

    SSL_write(ssl, msg, sizeof(msg));

    inet_ntop(AF_INET6, &ip, ip_str, sizeof(ip_str));
    printf("Message 5 envoyé : ID=%s, IP=%s, PORT=%u\n", id_peer, ip_str, port);

    // Wait for response (message 50 or 51)
    uint8_t response[3];
    int bytes_read = SSL_read(ssl, response, sizeof(response));
    if (bytes_read <= 0) {
        printf("Erreur lors de la lecture de la réponse.\n");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(socket_tcp_client);
        return -1;
    }

    if (response[0] == 50) {
        // Received message 50 - ID already taken, get new ID
        struct message_50 msg_50;
        if (parse_msg_50(response, bytes_read, &msg_50) == 0) {
            printf("ID déjà pris. Nouvel ID reçu : %u\n", msg_50.id);
            // Update peer's ID
            snprintf(id_peer, sizeof(id_peer), "%u", msg_50.id);
        }
    } else if (response[0] == 51) {
        // Received message 51 - ID accepted
        struct message_51 msg_51;
        if (parse_msg_51(response, bytes_read, &msg_51) == 0) {
            printf("ID accepté : %u\n", msg_51.id);
        }
    } else {
        printf("Message de réponse inattendu : %u\n", response[0]);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(socket_tcp_client);
        return -1;
    }

    return socket_tcp_client;
}
