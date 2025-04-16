#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sodium.h>
#include "../include/peer.h"
#include "../include/superviseur.h"
 

int active_peers = 0;
pthread_mutex_t peer_count_mutex;


int main() {

    // Initialisation de la bibliothèque Sodium
    if (sodium_init() == -1) {
        fprintf(stderr, "Erreur d'initialisation de Sodium\n");
        return 1;
    }

    pthread_mutex_init(&peer_count_mutex, NULL);
    pthread_t peer_threads[MAX_PEERS];

    int sock;
    struct sockaddr_in6 addr;
    struct ipv6_mreq group;

    sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return EXIT_FAILURE;
    }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(PORT);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Bind failed");
        close(sock);
        return EXIT_FAILURE;
    }

    inet_pton(AF_INET6, MULTICAST_GROUP, &group.ipv6mr_multiaddr);
    group.ipv6mr_interface = 0;
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &group, sizeof(group)) < 0) {
        perror("Joining multicast group failed");
        close(sock);
        return EXIT_FAILURE;
    }

    for (int i = 0; i < MAX_PEERS; i++) {
        if (pthread_create(&peer_threads[i], NULL, peer_handler, (void *)&sock) != 0) {
            perror("Failed to create peer thread");
        }
    }

    for (int i = 0; i < MAX_PEERS; i++) {
        pthread_join(peer_threads[i], NULL);
    }

    pthread_mutex_destroy(&peer_count_mutex);
    close(sock);
    return 0;
}
