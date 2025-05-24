#ifndef ENCHERE_H
#define ENCHERE_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
// #include "peer.h"

typedef struct Vente {
    int numv; // id unique
    uint32_t prix_courant;
    // uint16_t id_gagnant;
    struct Vente *next;
} Vente;

typedef struct {
    int sock;           // Socket de l'enchère
    // char group[INET6_ADDRSTRLEN];  // Groupe de l'enchère
    pthread_t thread_id; // ID du thread d'écoute
    struct in6_addr group; // Adresse IPv6 du groupe d'enchère
    int id_enchere;     // ID de l'enchère
    int port_enchere; // Port de l'enchère
    int nb_pairs; // Nombre de pairs dans l'enchère

    Vente *ventes; // Liste des ventes associées à l'enchère
    int nb_ventes;
    // int numv; // Numéro de la vente

    struct peer_list *liste_participants; // Liste des pairs de cette enchère

    int is_superviseur; // Indique si le pair est superviseur d'une vente
    int numv_supervise; // vente supervisé 
    int my_id;
    int consensus;
    int nb_msg_1;
    pthread_t tid_consensus;
    int superviseur_actif;  // variable de contrôle
    pthread_mutex_t superviseur_mutex;
    pthread_cond_t superviseur_cond;

} EnchereSocket;

// Function declarations
void afficher_enncheres();
void creer_enchere();
int join_enchere(int id, char *group, uint16_t port);
// void faire_offre(uint32_t prix);
void faire_offre_sur_vente(int numv, uint32_t prix);
void afficher_vente(Vente *ventes);
int msg_join_enchere();
int init_vente();
int sur_enchere();
int send_msg_enchere(uint8_t *msg, size_t len, int num_enchere, int sock);
void mettre_fin();
int clean_encheres(int id_enchere);
int handle_peer_disappearance(uint16_t *absent_peer_ids, uint16_t num_absent);

Vente* ajouter_vente(EnchereSocket *enchere, int numv, uint32_t prix_courant);
int supprimer_vente(EnchereSocket *enchere, int numv);
Vente* rechercher_vente(EnchereSocket *enchere, int numv);
void free_ventes(Vente *ventes);
void update_vente(EnchereSocket *enchere, int numv, uint32_t nouveau_prix);

#endif // ENCHERE_H