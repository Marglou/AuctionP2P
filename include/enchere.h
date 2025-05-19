#ifndef ENCHERE_H
#define ENCHERE_H

#include <stdint.h>
#include <netinet/in.h>

void afficher_enncheres();
void creer_enchere();
int join_enchere(int id, char *group, uint16_t port);

void faire_offre(uint32_t prix);

// Rejoindre une enchère
int msg_join_enchere();
int init_vente ();
int sur_enchere();

int send_msg_enchere(uint8_t *msg, size_t len, int num_enchere);

#endif // ENCHERE_H