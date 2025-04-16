#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "../include/peer.h"
#include "../include/superviseur.h"
#include "../include/message.h"


#define MULTICAST_GROUP "ff02::1"  // IPv6 multicast group
#define PORT 12345
#define BUFFER_SIZE 1024
#define MAX_PEERS 4 //max number of peers in the auction system

// to keep track of the number of active peers
extern int active_peers;
extern pthread_mutex_t peer_count_mutex;

Superviseur superviseur;
int is_superviseur = 0; // Flag pour vérifier si c'est le superviseur
int supervisor_id = 0; // ID du superviseur

// to handle receiving multicast messages
void *start_listener(void *arg) {
    int sock = *((int *)arg);  // Cast arg to socket descriptor
    struct sockaddr_in6 addr;
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, sizeof(buffer));

    // Receive messages
    while (1) {
        socklen_t addrlen = sizeof(addr);
        int bytes_received = recvfrom(sock, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&addr, &addrlen);
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            printf("Received: %s\n", buffer);
        }
    }

    return NULL;
}

// to send multicast messages
void send_multicast_message(int sock, struct sockaddr_in6 *multicast_addr, const char *message) {
    if (sendto(sock, message, strlen(message), 0, (struct sockaddr *)multicast_addr, sizeof(*multicast_addr)) < 0) {
        perror("Sending multicast message failed");
    } else {
        printf("Sent multicast message: %s\n", message);
    }
}

void *peer_handler(void *arg) {
    int sock = *((int *)arg);  // Get the socket passed from main
    pthread_mutex_lock(&peer_count_mutex);
    if (active_peers >= MAX_PEERS) {
        pthread_mutex_unlock(&peer_count_mutex);
        printf("Max peer limit reached. Cannot join the auction.\n");
        return NULL;
    }
    active_peers++;
    pthread_mutex_unlock(&peer_count_mutex);

    printf("Peer joined. Active peers: %d\n", active_peers);

    // Créer un pair avec un identifiant unique
    Peer peer;
    peer.id = active_peers;  // Assigner l'id du pair
    generate_keys_for_peer(&peer);  // Générer les clés pour ce pair


    struct sockaddr_in6 multicast_addr;  // Declare the multicast address here
    // Set up multicast address for peer's usage
    memset(&multicast_addr, 0, sizeof(multicast_addr));
    multicast_addr.sin6_family = AF_INET6;
    multicast_addr.sin6_port = htons(PORT);
    inet_pton(AF_INET6, MULTICAST_GROUP, &multicast_addr.sin6_addr);

    // Start the listener thread and pass the socket to it
    pthread_t listener_thread;
    if (pthread_create(&listener_thread, NULL, start_listener, (void *)&sock) != 0) {
        perror("Failed to create listener thread");
        close(sock);
        return NULL;
    }

    // Simulate sending an auction message
    sleep(2);  // Ensure listener is running

    // Si ce pair est le premier, il devient le superviseur
    if (active_peers == 1) {
        supervisor_id = peer.id;  // Le premier pair devient le superviseur
        printf("Peer %d is the supervisor.\n", peer.id);
        is_superviseur = 1;
        send_multicast_message(sock, &multicast_addr, "Démarrage de l'enchère : Item X starting at 100 units");

    } else {
        // Si ce n'est pas le superviseur, on envoie la clé publique au superviseur
        if (!is_superviseur) {
            struct sockaddr_in6 superviseur_addr;
            memset(&superviseur_addr, 0, sizeof(superviseur_addr));
            superviseur_addr.sin6_family = AF_INET6;
            superviseur_addr.sin6_port = htons(PORT);
            printf("Peer %d: Envoi de la clé publique au superviseur...\n", peer.id);
            // On utilise ici l'ID du superviseur stocké pour déterminer l'adresse du superviseur 
            inet_pton(AF_INET6, "", &superviseur_addr.sin6_addr);  
            envoyer_cle_publique(sock, peer.id, peer.public_key, &superviseur_addr);
        }
    }

    send_multicast_message(sock, &multicast_addr, "New auction: Item X starting at 100 units");

    // Wait for listener thread to finish
    pthread_join(listener_thread, NULL);

    // Peer leaving the auction
    pthread_mutex_lock(&peer_count_mutex);
    active_peers--;
    pthread_mutex_unlock(&peer_count_mutex);
    printf("Peer left. Active peers: %d\n", active_peers);

    close(sock);
    return NULL;
}



// Fonction pour générer des clés pour un pair
void generate_keys_for_peer(Peer *peer) {
    if (crypto_sign_keypair(peer->public_key, peer->private_key) != 0) {
        fprintf(stderr, "Erreur de génération de clés pour le pair\n");
        exit(EXIT_FAILURE);
    }
    printf("Clés générées pour le pair %d\n", peer->id);
}

int sign_message(const unsigned char *message, size_t message_len, unsigned char *signed_message, unsigned char *private_key) {
    unsigned long long signed_message_len;
    
    if (crypto_sign(signed_message, &signed_message_len, message, message_len, private_key) != 0) {
        fprintf(stderr, "Erreur lors de la signature du message.\n");
        return -1;
    }
    
    return signed_message_len;
}

int verify_signature(const unsigned char *message, size_t message_len, const unsigned char *signature, const unsigned char *public_key) {
    if (crypto_sign_verify_detached(signature, message, message_len, public_key) != 0) {
        return -1;  // Signature invalide
    }
    return 0;  // Signature valide
}

void envoyer_cle_publique(int sock, uint16_t id, unsigned char *public_key, struct sockaddr_in6 *superviseur_addr) {
    PublicKeyMessage msg;
    msg.code = PUBLIC_KEY_MSG_CODE;
    msg.id = htons(id);
    memcpy(msg.public_key, public_key, crypto_sign_PUBLICKEYBYTES);

    sendto(sock, &msg, sizeof(msg), 0, (struct sockaddr*)superviseur_addr, sizeof(*superviseur_addr));
}
