#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

#define MULTICAST_GROUP "ff02::1"  // IPv6 multicast group
#define PORT 12345
#define BUFFER_SIZE 1024
#define MAX_PEERS 4 //max number of peers in the auction system

// to keep track of the number of active peers
int active_peers = 0;
pthread_mutex_t peer_count_mutex;

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

int main() {
    pthread_mutex_init(&peer_count_mutex, NULL);
    pthread_t peer_threads[MAX_PEERS];

    // Create socket once in the main thread
    int sock;
    struct sockaddr_in6 addr;
    struct ipv6_mreq group;
    struct sockaddr_in6 multicast_addr;  // Store multicast address here
    
    sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return EXIT_FAILURE;
    }

    // Allow multiple sockets to use the same port (reuse address)
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Bind to multicast address
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(PORT);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Bind failed");
        close(sock);
        return EXIT_FAILURE;
    }

    // Set up multicast address in main once
    memset(&multicast_addr, 0, sizeof(multicast_addr));
    multicast_addr.sin6_family = AF_INET6;
    multicast_addr.sin6_port = htons(PORT);
    inet_pton(AF_INET6, MULTICAST_GROUP, &multicast_addr.sin6_addr);

    // Join multicast group
    inet_pton(AF_INET6, MULTICAST_GROUP, &group.ipv6mr_multiaddr);
    group.ipv6mr_interface = 0;
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &group, sizeof(group)) < 0) {
        perror("Joining multicast group failed");
        close(sock);
        return EXIT_FAILURE;
    }

    // Simulate up to 4 peers joining the auction
    for (int i = 0; i < MAX_PEERS; i++) {
        if (pthread_create(&peer_threads[i], NULL, peer_handler, (void *)&sock) != 0) {
            perror("Failed to create peer thread");
        }
    }

    // Wait for all peer threads to finish
    for (int i = 0; i < MAX_PEERS; i++) {
        pthread_join(peer_threads[i], NULL);
    }

    pthread_mutex_destroy(&peer_count_mutex);
    close(sock);
    return 0;
}

