#ifndef ENCHERE_H
#define ENCHERE_H

#include <stdint.h>
#include <netinet/in.h>


void creer_enchere();
void join_enchere(const char *id, const char *group);

// Rejoindre une enchère
int msg_join_enchere();
void repondre_demande_liaison(int socket_udp, struct sockaddr_in6 *peer_addr, uint16_t id_local, int socket_tcp, struct in6_addr ip_perso);
int handle_incoming_connections(char *ip_dest, uint16_t *port_dest);

#endif // ENCHERE_H