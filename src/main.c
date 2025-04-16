//main.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sodium.h>

#include "../include/peer.h"
#include "../include/superviseur.h"
#include "../include/message.h"

#define SUPERVISEUR_ID 1

int active_peers = 0;
pthread_mutex_t peer_count_mutex;

int sock;

//handler pour la communication avec le superviseur
void* superviseur_handler(void* arg) {
    Superviseur *superviseur = (Superviseur*)arg;
    printf("Superviseur ID: %d\n", superviseur->id);
    handler_superviseur(&sock);  // Calls the superviseur handler function
    return NULL;
}

void* listener_handler(void* arg) {
    int sock = *(int*)arg;
    start_listener(&sock);
    return NULL;
}

int main() {
    // Initialisation de la bibliothèque Sodium
    if (sodium_init() == -1) {
        fprintf(stderr, "Erreur d'initialisation de Sodium\n");
        return 1;
    }

    pthread_mutex_init(&peer_count_mutex, NULL);
    pthread_t peer_threads[MAX_PEERS];

    Superviseur superviseur;
    init_superviseur(&superviseur, SUPERVISEUR_ID, SUPERVISEUR_PORT);

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
    addr.sin6_port = htons(PEER_PORT);

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

    // Create the thread for superviseur handler
    pthread_t superviseur_thread;
    if (pthread_create(&superviseur_thread, NULL, superviseur_handler, (void *)&superviseur) != 0) {
        perror("Failed to create superviseur thread");
        close(sock);
        return EXIT_FAILURE;
    }

    // Start peer listener thread
    pthread_t listener_thread;
    if (pthread_create(&listener_thread, NULL, listener_handler, (void *)&sock) != 0) {
        perror("Failed to create listener thread");
        close(sock);
        return EXIT_FAILURE;
    }

    // Multicast a join request
    struct sockaddr_in6 multicast_addr;
    memset(&multicast_addr, 0, sizeof(multicast_addr));
    multicast_addr.sin6_family = AF_INET6;
    multicast_addr.sin6_port = htons(PEER_PORT);
    inet_pton(AF_INET6, MULTICAST_GROUP, &multicast_addr.sin6_addr);

    send_multicast_message(sock, &multicast_addr, "Demande de rejoindre l'enchère");

    for (int i = 0; i < MAX_PEERS; i++) {
        if (pthread_create(&peer_threads[i], NULL, peer_handler, (void *)&sock) != 0) {
            perror("Failed to create peer thread");
        }
    }

    for (int i = 0; i < MAX_PEERS; i++) {
        pthread_join(peer_threads[i], NULL);
    }

    pthread_join(listener_thread, NULL);
    pthread_join(superviseur_thread, NULL);

    pthread_mutex_destroy(&peer_count_mutex);
    close(sock);
    return 0;
}
