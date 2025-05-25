// superviseur.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <time.h>

#include "../include/superviseur.h"
#include "../include/peer.h"
#include "../include/message.h"
#include "../include/enchere.h"
#include "../include/utils.h"


// Track current auction state
uint32_t current_price = 0;
uint32_t current_numv = 0;
uint16_t current_bidder = 0;
int count_offre = 0;

time_t last_bid_time = 0;
int warning_sent = 0;


void init_auction_supervisor(uint32_t numv, uint32_t prix) {
    p.encheres[p.enchere_active].is_superviseur = 1;
    current_price = prix;
    current_numv = numv;
    current_bidder = 0;
    count_offre = 0;
}

void cleanup_auction_supervisor() {
    p.encheres[p.enchere_active].is_superviseur = 0;
    enchere_supervise = 0;
    current_price = 0;
    current_numv = 0;
    current_bidder = 0;
    count_offre = 0;
}

void reset_auction_timer() {
    last_bid_time = time(NULL);
   // warning_sent = 0;
}

void check_auction_timeout() {

    time_t current_time = time(NULL);
    time_t elapsed = current_time - last_bid_time;

    if (warning_sent==0){
        uint8_t warning_msg[11];
        if (msg_11(warning_msg, p.id_peer, current_numv, current_price) == 11) {
            send_msg_enchere(warning_msg, 11, p.enchere_active, p.encheres[p.enchere_active].sock);
            printf("[Superviseur] Envoi de l'avertissement de finalisation\n");
            warning_sent = 1;
            return;
        }
    }
    else if (warning_sent == 1) {
        uint8_t final_msg[12];
        if (msg_12(final_msg, current_bidder, current_numv, current_price) == 11) {
            send_msg_enchere(final_msg, 11, p.enchere_active, p.encheres[p.enchere_active].sock);
            printf("[Superviseur] Finalisation de l'enchère - Gagnant: pair %u, Prix: %u NUMV %d\n", 
                   current_bidder, current_price, current_numv);
            
            cleanup_auction_supervisor();

            uint8_t relay_msg[11];
            if (msg_8_9_10(relay_msg, 10, current_bidder, current_numv, current_price) == 11) {
                send_msg_enchere(relay_msg, 11, p.enchere_active, p.socket_udp);
            }
           
        } 
    }
}

int validate_bid(uint16_t bidder_id, uint32_t numv, uint32_t prix) {
    if (p.encheres[p.enchere_active].is_superviseur==0) {
        return -1;
    }
    
    if (prix <= rechercher_vente(&p.encheres[p.enchere_active], numv)->prix_courant) {
        
        uint8_t reject_msg[11];
        if (msg_14_15(reject_msg, 15, bidder_id, numv, prix) == 11) {
            send_msg_enchere(reject_msg, 11, p.enchere_active, p.encheres[p.enchere_active].sock);
            count_offre = 0;
            printf("[Superviseur] Rejet de l'offre trop basse de pair %u\n", bidder_id);
        }
        return -1;
    }

    
    if(p.encheres[p.enchere_active].consensus==1){
            
        if (numv == p.encheres[enchere_supervise].numv_supervise && count_offre > 0) {
            
            uint8_t reject_msg[11];
            if (msg_14_15(reject_msg, 14, bidder_id, numv, prix) == 11) {
                send_msg_enchere(reject_msg, 11, p.enchere_active, p.encheres[p.enchere_active].sock);
                printf("[Superviseur] Rejet de l'offre concurrente de pair %u\n", bidder_id);
            }
            return -1;
        }  
    }

    uint8_t relay_msg[11];
    if (msg_8_9_10(relay_msg, 10, bidder_id, numv, prix) == 11) {
        send_msg_enchere(relay_msg, 11, p.enchere_active, p.socket_udp);

        printf("[Superviseur] Validation de l'offre de pair %u\n", bidder_id);

        current_price = prix;
        current_bidder = bidder_id;
        count_offre++;
        
        reset_auction_timer();   
        return 0;
    }
    return -1;
}

void handle_auction_message(uint8_t code, uint16_t id, uint32_t numv, uint32_t prix) {
    reset_auction_timer();
    switch (code) {
        case 8: 
            printf("[Enchère] Nouvelle vente initiée par pair %u: NUMV=%u, PRIX=%u\n", 
                   id, numv, prix);
            
            if (rechercher_vente(&p.encheres[p.enchere_active], numv) != NULL) {
                break;
            }
            if (ajouter_vente(&p.encheres[p.enchere_active], numv, prix) == NULL){
                printf("Erreur d'ajout de la vente \n");
                break;
            }
            p.encheres[p.enchere_active].nb_ventes++;
            break;
            
        case 9: 
            printf("[Enchère] Nouvelle offre de pair %u: NUMV=%u, PRIX=%u\n", 
                   id, numv, prix);
            
           
            if (p.encheres[p.enchere_active].is_superviseur == 1 && p.encheres[p.enchere_active].numv_supervise == numv) {
                p.encheres[p.enchere_active].consensus = 1;
                validate_bid(id, numv, prix);
                break;
            }
            
            if (rechercher_vente(&p.encheres[p.enchere_active], numv) != NULL) {
                // printf("Enchere deja presente\n");
                break;
            }

            if (ajouter_vente(&p.encheres[p.enchere_active], numv, prix) == NULL){
                printf("Erreur d'ajout de la vente \n");
                break;
            }
            p.encheres[p.enchere_active].nb_ventes++;
            break;
            
        case 14: // Rejected bid (competing)
            printf("[Enchère] Offre rejetée (concurrente) de pair %u: NUMV=%u, PRIX=%u\n", 
                   id, numv, prix);
            break;
            
        case 15: // Rejected bid (too low)
            printf("[Enchère] Offre rejetée (trop basse) de pair %u: NUMV=%u, PRIX=%u\n", 
                   id, numv, prix);
            break;
            
        case 11: // Finalization warning
            printf("[Enchère] Avertissement de finalisation reçu\n");
            break;
            
        case 12: // Finalization message
            printf("[Enchère] Enchère finalisée code 12 - Gagnant: pair %u, Prix: %u\n", 
                   id, prix);
            if(id==p.encheres[p.enchere_active].my_id){
                decrementer_compte(prix);
            }else if(is_superviseur==1 && p.encheres[p.enchere_active].numv_supervise==numv){
                incrementer_compte(prix);
            }
            p.encheres[p.enchere_active].numv_supervise = 0;
            supprimer_vente(&p.encheres[p.enchere_active], numv);
            p.encheres[p.enchere_active].nb_ventes--;
            
            break;
    }
}

