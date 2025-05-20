//superviseur.h
#ifndef SUPERVISEUR_H
#define SUPERVISEUR_H

#include <stdint.h>

// Global variables for auction supervision
extern int is_superviseur;
extern int enchere_supervise;

// Initialize supervisor state
void init_auction_supervisor();

// Clean up supervisor state
void cleanup_auction_supervisor();

// Validate a bid and handle rejection/acceptance
int validate_bid(uint16_t bidder_id, uint32_t numv, uint32_t prix);

// Handle auction-related messages
void handle_auction_message(uint8_t code, uint16_t id, uint32_t numv, uint32_t prix);

#endif
