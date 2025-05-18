//utils.h
#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include "peer.h"
#include "enchere.h"
#include "superviseur.h"
#include "message.h"
#include "connexion.h"

int get_active_interface();
int get_ipv6_address(char *buf, size_t buflen);
int generer_id_peer();
int generate_random_port();
void free_peer_list(struct peer *head);

int create_perso_adr_sockets(struct sockaddr_in6 ip, unsigned int scope_id, int *tcp_sock, int *udp_sock, uint16_t port);

void print_peer_list(struct peer *head);
int get_adresse_perso_par_index(struct in6_addr *addr, unsigned int iface_index);
int send_multicast(int sock, char *msg, size_t msg_len);
int send_UDP(int sock, struct sockaddr_in6 *multicast_addr, char *msg, size_t msg_len);

#endif // UTILS_H
