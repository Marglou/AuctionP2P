//superviseur.h
#ifndef SUPERVISEUR_H
#define SUPERVISEUR_H

#include <stdint.h>

// Global variables for auction supervision
extern int is_superviseur;
extern int enchere_supervise;
extern uint16_t current_bidder;
// void init_auction_supervisor();
void init_auction_supervisor(uint32_t numv, uint32_t prix);
void cleanup_auction_supervisor();

// Timer management
void reset_auction_timer();
void check_auction_timeout();

// Validate a bid and handle rejection/acceptance
int validate_bid(uint16_t bidder_id, uint32_t numv, uint32_t prix);

// Handle auction-related messages
void handle_auction_message(uint8_t code, uint16_t id, uint32_t numv, uint32_t prix);

#endif
