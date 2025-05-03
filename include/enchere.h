#ifndef ENCHERE_H
#define ENCHERE_H

#include <stdint.h>
#include <netinet/in.h>


void creer_enchere();
void join_enchere(const char *id, const char *group);
void faire_offre(uint32_t prix);

// Rejoindre une enchère
int msg_join_enchere();
// int handle_incoming_connections(char *ip_dest, uint16_t *port_dest);

#endif // ENCHERE_H