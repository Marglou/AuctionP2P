#ifndef ENCHERE_H
#define ENCHERE_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include "peer.h"

// Constants
//#define MAX_ENCHERES 10
//#define MAX_PEERS 100
#define BUF_SIZE 1024
//#define GROUP "ff02::abcd"
//#define PORT 12345

// Function declarations
void afficher_enncheres();
void creer_enchere();
int join_enchere(int id, char *group, uint16_t port);
void faire_offre(uint32_t prix);
int msg_join_enchere();
int init_vente();
int sur_enchere();
int send_msg_enchere(uint8_t *msg, size_t len, int num_enchere, int sock);
void mettre_fin();
int clean_encheres(int id_enchere);
int handle_peer_disappearance(uint16_t *absent_peer_ids, uint16_t num_absent);

#endif // ENCHERE_H