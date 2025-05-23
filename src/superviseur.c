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

// Timer variables for auction finalization
#define INACTIVITY_TIMEOUT 3  // 30 seconds of inactivity before warning
#define FINALIZATION_TIMEOUT 3  // 30 seconds after warning before finalization
time_t last_bid_time = 0;
int warning_sent = 0;


void init_auction_supervisor(uint32_t numv, uint32_t prix) {
    p.encheres[p.enchere_active].is_superviseur = 1;
    current_price = prix;
    current_numv = numv;
    current_bidder = 0;
}

void cleanup_auction_supervisor() {
    p.encheres[p.enchere_active].is_superviseur = 0;
    enchere_supervise = 0;
    current_price = 0;
    current_numv = 0;
    current_bidder = 0;
}

void reset_auction_timer() {
    last_bid_time = time(NULL);
    warning_sent = 0;
}

void check_auction_timeout() {

    time_t current_time = time(NULL);
    time_t elapsed = current_time - last_bid_time;

    // If no warning sent and timeout reached, send warning
    // if (!warning_sent && elapsed >= INACTIVITY_TIMEOUT) {
    if (warning_sent==0){
        printf("i'm here\n");
        uint8_t warning_msg[11];
        if (msg_11(warning_msg, p.id_peer, current_numv, current_price) == 11) {
            send_msg_enchere(warning_msg, 11, p.enchere_active, p.encheres[p.enchere_active].sock);
            printf("[Superviseur] Envoi de l'avertissement de finalisation\n");
            warning_sent = 1;
            return;
        }
    }
    // If warning was sent and final timeout reached, finalize auction
    // else if (warning_sent && elapsed >= (INACTIVITY_TIMEOUT + FINALIZATION_TIMEOUT)) {
    else if (warning_sent) {
        uint8_t final_msg[12];
        if (msg_12(final_msg, current_bidder, current_numv, current_price) == 11) {
            send_msg_enchere(final_msg, 11, p.enchere_active, p.encheres[p.enchere_active].sock);
            printf("[Superviseur] Finalisation de l'enchère - Gagnant: pair %u, Prix: %u\n", 
                   current_bidder, current_price);
            
            // Clean up supervisor state
            cleanup_auction_supervisor();

            uint8_t relay_msg[11];
            if (msg_8_9_10(relay_msg, 10, current_bidder, current_numv, current_price) == 11) {
                send_msg_enchere(relay_msg, 11, p.enchere_active, p.socket_udp);
            }
           
        } 
        //return;
    }
}

int validate_bid(uint16_t bidder_id, uint32_t numv, uint32_t prix) {
    if (!is_superviseur) {
        return -1;
    }

    // Check if this is a competing bid
    if (numv != p.encheres[enchere_supervise].numv) {
        // Reject competing bid (code 14)
        uint8_t reject_msg[11];
        if (msg_14_15(reject_msg, 14, bidder_id, numv, prix) == 11) {
            send_msg_enchere(reject_msg, 11, p.enchere_active, p.encheres[p.enchere_active].sock);
            printf("[Superviseur] Rejet de l'offre concurrente de pair %u\n", bidder_id);
        }
        return -1;
    }

    // Check if bid price is lower than current price
    if (prix <= current_price) {
        // Reject low bid (code 15)
        uint8_t reject_msg[11];
        if (msg_14_15(reject_msg, 15, bidder_id, numv, prix) == 11) {
            send_msg_enchere(reject_msg, 11, p.enchere_active, p.encheres[p.enchere_active].sock);
            printf("[Superviseur] Rejet de l'offre trop basse de pair %u\n", bidder_id);
        }
        return -1;
    }

    // Valid bid - relay with code 10
    uint8_t relay_msg[11];
    if (msg_8_9_10(relay_msg, 10, bidder_id, numv, prix) == 11) {
        send_msg_enchere(relay_msg, 11, p.enchere_active, p.socket_udp);

        printf("[Superviseur] Validation de l'offre de pair %u\n", bidder_id);

        // Update current auction state
        current_price = prix;
        current_bidder = bidder_id;
        // Reset the auction timer
        reset_auction_timer();   
        return 0;
    }
    return -1;
}

void handle_auction_message(uint8_t code, uint16_t id, uint32_t numv, uint32_t prix) {
    switch (code) {
        case 8: // Auction initiation
            printf("[Enchère] Nouvelle vente initiée par pair %u: NUMV=%u, PRIX=%u\n", 
                   id, numv, prix);
            
            // // Update auction state
            // current_price = prix;
            // current_numv = numv;
            // current_bidder = id;
            
            // // Store auction info
            p.encheres[p.enchere_active].numv = numv;
            // enchere_supervise = p.enchere_active;
            // is_superviseur = 1;
            
            // // Initialize timer
            // reset_auction_timer();
            break;
            
        case 9: // Bid message
            printf("[Enchère] Nouvelle offre de pair %u: NUMV=%u, PRIX=%u\n", 
                   id, numv, prix);
            
            // If we are the supervisor, validate the bid
            if (is_superviseur) {
                validate_bid(id, numv, prix);
            }
            break;
            
        // case 10: // Relayed bid message
            // printf("[Enchère] Offre validée de pair %u: NUMV=%u, PRIX=%u\n", 
            //        id, numv, prix);
            
            // // Update current auction state
            // current_price = prix;
            // // current_bidder = id;
            // printf("[ENCHERE] : message 10 recu : debut consensus \n");
            // uint8_t consensus_msg[11];
            // if (msg_1(consensus_msg, id, "Consensus") == 11) {
            //     send_msg_enchere(consensus_msg, 11, p.enchere_active);
            //     printf("[Superviseur] Envoi du message de consensus à pair %u\n", id);
            // }
            // break;
            
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
            // p.encheres[p.enchere_active].is_superviseur = 0;
            p.encheres[p.enchere_active].numv = 0;
            break;
    }
}

