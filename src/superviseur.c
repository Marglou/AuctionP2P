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

#include "../include/superviseur.h"
#include "../include/peer.h"
#include "../include/message.h"
#include "../include/enchere.h"
#include "../include/utils.h"

// Global variables for auction supervision
extern int is_superviseur;
extern int enchere_supervise;

// Track current auction state
uint32_t current_price = 0;
uint32_t current_numv = 0;
uint16_t current_bidder = 0;

void init_auction_supervisor() {
    is_superviseur = 1;
    current_price = 0;
    current_numv = 0;
    current_bidder = 0;
}

void cleanup_auction_supervisor() {
    is_superviseur = 0;
    enchere_supervise = 0;
    current_price = 0;
    current_numv = 0;
    current_bidder = 0;
}

int validate_bid(uint16_t bidder_id, uint32_t numv, uint32_t prix) {
    if (!is_superviseur) {
        return -1;
    }

    // Check if this is a competing bid
    if (numv != current_numv) {
        // Reject competing bid (code 14)
        uint8_t reject_msg[11];
        if (msg_14_15(reject_msg, 14, bidder_id, numv, prix) == 11) {
            send_msg_enchere(reject_msg, 11, p.enchere_active);
            printf("[Superviseur] Rejet de l'offre concurrente de pair %u\n", bidder_id);
        }
        return -1;
    }

    // Check if bid price is lower than current price
    if (prix <= current_price) {
        // Reject low bid (code 15)
        uint8_t reject_msg[11];
        if (msg_14_15(reject_msg, 15, bidder_id, numv, prix) == 11) {
            send_msg_enchere(reject_msg, 11, p.enchere_active);
            printf("[Superviseur] Rejet de l'offre trop basse de pair %u\n", bidder_id);
        }
        return -1;
    }

    // Valid bid - relay with code 10
    uint8_t relay_msg[11];
    if (msg_8_9_10(relay_msg, 10, bidder_id, numv, prix) == 11) {
        send_msg_enchere(relay_msg, 11, p.enchere_active);
        printf("[Superviseur] Validation de l'offre de pair %u\n", bidder_id);
        
        // Update current auction state
        current_price = prix;
        current_bidder = bidder_id;
        return 0;
    }

    return -1;
}

void handle_auction_message(uint8_t code, uint16_t id, uint32_t numv, uint32_t prix) {
    switch (code) {
        case 8: // Auction initiation
            printf("[Enchère] Nouvelle enchère initiée par pair %u: NUMV=%u, PRIX=%u\n", 
                   id, numv, prix);
            
            // Update auction state
            current_price = prix;
            current_numv = numv;
            current_bidder = id;
            
            // Store auction info
            p.encheres[p.enchere_active].numv = numv;
            break;
            
        case 9: // Bid message
            printf("[Enchère] Nouvelle offre de pair %u: NUMV=%u, PRIX=%u\n", 
                   id, numv, prix);
            
            // If we are the supervisor, validate the bid
            if (is_superviseur) {
                validate_bid(id, numv, prix);
            }
            break;
            
        case 10: // Relayed bid message
            printf("[Enchère] Offre validée de pair %u: NUMV=%u, PRIX=%u\n", 
                   id, numv, prix);
            
            // Update current auction state
            current_price = prix;
            current_bidder = id;
            break;
            
        case 14: // Rejected bid (competing)
            printf("[Enchère] Offre rejetée (concurrente) de pair %u: NUMV=%u, PRIX=%u\n", 
                   id, numv, prix);
            break;
            
        case 15: // Rejected bid (too low)
            printf("[Enchère] Offre rejetée (trop basse) de pair %u: NUMV=%u, PRIX=%u\n", 
                   id, numv, prix);
            break;
    }
}

