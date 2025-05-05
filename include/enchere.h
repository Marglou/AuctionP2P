#ifndef ENCHERE_H
#define ENCHERE_H

#include <stdint.h>
#include <netinet/in.h>


void creer_enchere();
// void join_enchere(int id, const char *group);
int join_enchere(int id,  char *group);

void faire_offre(uint32_t prix);

// Rejoindre une enchère
int msg_join_enchere();

#endif // ENCHERE_H