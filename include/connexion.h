#ifndef CONNEXION_H
#define CONNEXION_H


struct tcp_listener_state {
    int socket_tcp;
    volatile int response_received;
    time_t first_response_time;
};


void *listen_tcp_thread(void *arg);
int connexion_TLS(struct in6_addr ip, uint16_t port);

#endif // CONNEXION_H