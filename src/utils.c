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
#include <ifaddrs.h>

#include "../include/utils.h"

#include <fcntl.h>  // pour fcntl()
#include <openssl/ssl.h>
#include <openssl/err.h>

int set_socket_nonblocking(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl(F_GETFL)");
        return -1;
    }

    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl(F_SETFL)");
        return -1;
    }

    return 0;  // succès
}


int get_active_interface() {
    struct ifaddrs *ifaddr, *ifa;
    
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET6 &&
            (ifa->ifa_flags & IFF_UP) &&
            !(ifa->ifa_flags & IFF_LOOPBACK)) {

            char* res = ifa->ifa_name;
            freeifaddrs(ifaddr);
            return if_nametoindex(res);
        }
    }

    freeifaddrs(ifaddr);
    return -1;
}

void print_peer_list(peer_list *head) {
    peer_list *current = head;
    int count = 0;

    while (current != NULL) {
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &current->ip, ip_str, sizeof(ip_str));
        printf("Peer %d: ID=%d, IP=%s, Port=%d\n", ++count, current->id, ip_str, current->port_tcp);
        current = current->next;
    }

    if (count == 0) {
        printf("La liste des participants est vide.\n");
    }
}

int get_ipv6_address(char *buf, size_t buflen) {
    struct ifaddrs *ifaddr, *ifa;
    int found = 0;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET6)
            continue;

        if (ifa->ifa_flags & IFF_LOOPBACK)
            continue;

        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)ifa->ifa_addr;

        // Ignorer les adresses :: (non spécifiées) et ::1 (loopback)
        if (IN6_IS_ADDR_LOOPBACK(&addr6->sin6_addr) ||
            IN6_IS_ADDR_UNSPECIFIED(&addr6->sin6_addr))
            continue;

        // Pour l’instant, on accepte les adresses lien-local (fe80::/10)
        // Si tu veux les exclure : if (IN6_IS_ADDR_LINKLOCAL(&addr6->sin6_addr)) continue;

        if (inet_ntop(AF_INET6, &addr6->sin6_addr, buf, buflen) != NULL) {
            found = 1;
            break;
        }
    }

    freeifaddrs(ifaddr);
    return found ? 0 : -1;
}

/*int get_ipv6_address(char *buf, size_t buflen) {
    struct ifaddrs *ifaddr, *ifa;
    int found = 0;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET6)
            continue;

        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)ifa->ifa_addr;

        // On ignore ::, ::1 et les adresses loopback
        if (IN6_IS_ADDR_LOOPBACK(&addr6->sin6_addr) ||
            IN6_IS_ADDR_UNSPECIFIED(&addr6->sin6_addr))
            continue;

        // Facultatif : ignorer les adresses lien-local
        if (IN6_IS_ADDR_LINKLOCAL(&addr6->sin6_addr)) {
            // Si tu veux accepter lien-local, enlève ce test
            // continue;
        }

        // Convertir en string
        if (inet_ntop(AF_INET6, &addr6->sin6_addr, buf, buflen) != NULL) {
            // *scope_id = addr6->sin6_scope_id; // utile si lien-local
            found = 1;
            break;
        }
    }

    freeifaddrs(ifaddr);
    return found ? 0 : -1;
}*/

int get_adresse_perso_par_index(struct in6_addr *addr, unsigned int iface_index) {
    struct ifaddrs *ifaddr, *ifa;
    
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET6)
            continue;

        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;

        // Vérifie que c'est la bonne interface par son index
        if (if_nametoindex(ifa->ifa_name) == iface_index) {
            memcpy(addr, &sin6->sin6_addr, sizeof(struct in6_addr));
            freeifaddrs(ifaddr);
            return 0;
        }
    }

    freeifaddrs(ifaddr);
    fprintf(stderr, "Adresse perso non trouvée pour index %u\n", iface_index);
    return -1;
}

int generate_random_port() {
    // Initialiser le générateur de nombres aléatoires
    srand(time(NULL));  
    int MIN_PORT = 1024; // Port minimum
    int MAX_PORT = 65535; // Port maximum
    
    // Générer un port aléatoire entre MIN_PORT et MAX_PORT
    return (rand() % (MAX_PORT - MIN_PORT + 1)) + MIN_PORT;
}

void free_peer_list(peer_list *head) {
    peer_list *current = head;
    peer_list *temp;

    while (current != NULL) {
        temp = current;
        current = current->next;
        free(temp);
    }
}

int generer_id_peer() {
    srand(time(NULL)); // Initialiser le générateur de nombres aléatoires
    return ((int)rand()%25);
}



// Fonction qui crée les deux sockets
int create_perso_adr_sockets(struct sockaddr_in6 ip, unsigned int scope_id,
                             int *tcp_sock, int *udp_sock,
                             uint16_t port) {
    
    char ip_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip.sin6_addr, ip_str, sizeof(ip_str));
    printf("IPv6: %s\n", ip_str);
    printf("Port: %d\n", ntohs(ip.sin6_port));
    printf("Scope ID: %u\n", ip.sin6_scope_id);

    // Créer socket TCP
    *tcp_sock = socket(PF_INET6, SOCK_STREAM, 0);
    if (*tcp_sock < 0) {
        perror("socket TCP");
        return -1;
    }

    int reuse = 1;
    // Réutilisation des adresses et des ports avant bind
    if (setsockopt(*tcp_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt TCP SO_REUSEADDR");
        close(*tcp_sock);
        return -1;
    }
    if (setsockopt(*tcp_sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt TCP SO_REUSEPORT");
        close(*tcp_sock);
        return -1;
    }

    if (bind(*tcp_sock, (struct sockaddr *)&ip, sizeof(ip)) < 0) {
        perror("bind TCP");
        close(*tcp_sock);
        return -1;
    }
    if (listen(*tcp_sock, 5) < 0) {
        perror("listen TCP");
        close(*tcp_sock);
        return -1;
    }

    // Création socket IPv6 UDP
    *udp_sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (*udp_sock < 0) {
        perror("socket");
        close(*tcp_sock);
        exit(EXIT_FAILURE);
    }

    // Réutilisation des adresses et des ports pour UDP avant bind
    if (setsockopt(*udp_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt UDP SO_REUSEADDR");
        close(*tcp_sock);
        close(*udp_sock);
        return -1;
    }
    if (setsockopt(*udp_sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt UDP SO_REUSEPORT");
        close(*tcp_sock);
        close(*udp_sock);
        return -1;
    }

    // Bind unicast socket
    if (bind(*udp_sock, (struct sockaddr*)&ip, sizeof(ip)) < 0) {
        perror("bind unicast");
        close(*udp_sock);
        close(*tcp_sock);
        return -1;
    }

    return 0;
} 

/* // Fonction qui crée les deux sockets
int create_perso_adr_sockets(struct sockaddr_in6 ip, unsigned int scope_id,
                             int *tcp_sock, int *udp_sock,
                             uint16_t port, char *priv) {
    
    char ip_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip.sin6_addr, ip_str, sizeof(ip_str));
    printf("IPv6: %s\n", ip_str);
    printf("Port: %d\n", ntohs(ip.sin6_port));
    printf("Scope ID: %u\n", ip.sin6_scope_id);


	// l'objet SSL_CTX ctx utilisera notre certificat signé par nous-même
	//    et notre clé
	if (!SSL_CTX_use_certificate_file(p.ctx, p.cert_path , SSL_FILETYPE_PEM) ||
	    !SSL_CTX_use_PrivateKey_file(p.ctx, priv, SSL_FILETYPE_PEM)) {
		fprintf(stderr, "echec SSL_CTX_use_certificate_file()\n");
		ERR_print_errors_fp(stderr);
		return 1;
	}

    // Créer socket TCP
    *tcp_sock = socket(PF_INET6, SOCK_STREAM, 0);
    if (*tcp_sock < 0) {
        perror("socket TCP");
        return -1;
    }

    int reuse = 1;
    // Réutilisation des adresses et des ports avant bind
    if (setsockopt(*tcp_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt TCP SO_REUSEADDR");
        close(*tcp_sock);
        return -1;
    }
    if (setsockopt(*tcp_sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt TCP SO_REUSEPORT");
        close(*tcp_sock);
        return -1;
    }

    if (bind(*tcp_sock, (struct sockaddr *)&ip, sizeof(ip)) < 0) {
        perror("bind TCP");
        close(*tcp_sock);
        return -1;
    }
    if (listen(*tcp_sock, 5) < 0) {
        perror("listen TCP");
        close(*tcp_sock);
        return -1;
    }

    // Création socket IPv6 UDP
    *udp_sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (*udp_sock < 0) {
        perror("socket");
        close(*tcp_sock);
        exit(EXIT_FAILURE);
    }

    // Réutilisation des adresses et des ports pour UDP avant bind
    if (setsockopt(*udp_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt UDP SO_REUSEADDR");
        close(*tcp_sock);
        close(*udp_sock);
        return -1;
    }
    if (setsockopt(*udp_sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt UDP SO_REUSEPORT");
        close(*tcp_sock);
        close(*udp_sock);
        return -1;
    }

    // Bind unicast socket
    if (bind(*udp_sock, (struct sockaddr*)&ip, sizeof(ip)) < 0) {
        perror("bind unicast");
        close(*udp_sock);
        close(*tcp_sock);
        return -1;
    }

    return 0;
} */

// Envoie un message sur une adresse multicast IPv6
int send_UDP (int sock, struct sockaddr_in6 *multicast_addr, char *msg, size_t msg_len) {
    ssize_t sent = sendto(sock, msg, msg_len, 0,
                          (struct sockaddr *)multicast_addr,
                          sizeof(multicast_addr));
    if (sent < 0) {
        perror("sendto multicast");
        return -1;
    }
    return 0; // Succès
}

int send_multicast (int sock, char *msg, size_t msg_len) {
    ssize_t sent = sendto(sock, msg, msg_len, 0,
                          (struct sockaddr *)&p.adr_liaison.addr,
                          sizeof(struct sockaddr_in6));
    if (sent < 0) {
        perror("sendto multicast");
        return -1;
    }
    return 0; // Succès
}