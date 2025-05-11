#ifndef ENCHERE_H
#define ENCHERE_H

#include <stdint.h>
#include <netinet/in.h>


void creer_enchere();
int join_enchere(int id, char *group, uint16_t port);

void faire_offre(uint32_t prix);

// Rejoindre une enchère
int msg_join_enchere();

#endif // ENCHERE_H