//superviseur.c

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sodium.h>

#include "../include/superviseur.h"
#include "../include/message.h"
#include"../include/peer.h"

#define MAX_PAIRS MAX_PEERS-1

void init_superviseur(Superviseur *s, uint16_t id, uint16_t port) {
    s->id = id;
    crypto_sign_keypair(s->public_key, s->private_key);

    memset(&s->addr, 0, sizeof(s->addr));
    s->addr.sin6_family = AF_INET6;
    s->addr.sin6_port = htons(port);
    s->addr.sin6_addr = in6addr_any;

    // printf("Superviseur initialisé avec ID: %d et Port: %d\n", id, port);
}

Peer known_peers[MAX_PAIRS];  // Tableau contenant les pairs connus (leurs clés publiques)
int total_peers = 0;              // Total de pairs attendus (hors superviseur)

typedef struct {
    uint16_t id_validators[MAX_PAIRS];
    int num_validations;
    char current_message[BUFFER_SIZE];
} ConsensusState;

ConsensusState consensus_state;

int has_already_validated(uint16_t id) {
    for (int i = 0; i < consensus_state.num_validations; ++i) {
        if (consensus_state.id_validators[i] == id)
            return 1;
    }
    return 0;
}

void* handler_superviseur(void* arg) {
    int sock = *((int*)arg);
    struct sockaddr_in6 addr;
    char buffer[BUFFER_SIZE];

    printf("[SUPERVISEUR] En attente des messages (clés publiques ou validations)...\n");

    while (1) {
        socklen_t addrlen = sizeof(addr);
        int received = recvfrom(sock, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&addr, &addrlen);
        if (received <= 0) continue;

        uint8_t code = buffer[0];

        // === Gestion de la réception d'une clé publique ===
        if (code == PUBLIC_KEY_MSG_CODE) {
            PublicKeyMessage *msg = (PublicKeyMessage *)buffer;
            uint16_t id = ntohs(msg->id);
        
            // Vérifie si déjà connu
            int already_known = 0;
            for (int i = 0; i < total_peers; i++) {
                if (known_peers[i].id == id) {
                    already_known = 1;
                    break;
                }
            }
        
            if (!already_known && total_peers < MAX_PAIRS) {
                known_peers[total_peers].id = id;
                memcpy(known_peers[total_peers].public_key, msg->public_key, crypto_sign_PUBLICKEYBYTES);
                total_peers++;
                printf("[SUPERVISEUR] Clé publique reçue du pair %d\n", id);
            }
        
            continue; // On passe au message suivant
        }
        

        // Réception d'une validation 
        if (code == 1) {
            ValidationMessageComplet *vmsg = (ValidationMessageComplet *)buffer;
            uint16_t id = ntohs(vmsg->id);

            if (!has_already_validated(id)) {
                consensus_state.id_validators[consensus_state.num_validations++] = id;
                printf("[SUPERVISEUR] Validation reçue du pair %d\n", id);
            }

            // Check if we have all validations
            if (consensus_state.num_validations >= total_peers) {
                printf("[SUPERVISEUR] Toutes les validations reçues. Signature et diffusion du message final.\n");

                // Signature du message
                unsigned char signed_msg[BUFFER_SIZE + crypto_sign_BYTES];
                unsigned long long signed_len;
                crypto_sign(signed_msg, &signed_len, 
                    (unsigned char*)consensus_state.current_message, strlen(consensus_state.current_message),
                    ((Superviseur*)arg)->private_key);

                // Préparation du message code 2/20
                FinalMessage final_msg;
                final_msg.code = 2;
                final_msg.superviseur_id = htons(((Superviseur*)arg)->id);
                memcpy(final_msg.message, signed_msg, signed_len);
                final_msg.lmess = htonl(signed_len);

                // Multidiffusion
                struct sockaddr_in6 multicast_addr;
                memset(&multicast_addr, 0, sizeof(multicast_addr));
                multicast_addr.sin6_family = AF_INET6;
                multicast_addr.sin6_port = htons(PEER_PORT);
                inet_pton(AF_INET6, MULTICAST_GROUP, &multicast_addr.sin6_addr);

                sendto(sock, &final_msg, sizeof(FinalMessage), 0,
                       (struct sockaddr*)&multicast_addr, sizeof(multicast_addr));
                printf("[SUPERVISEUR] Message final diffusé.\n");

                // Reset pour prochain consensus
                consensus_state.num_validations = 0;
                memset(consensus_state.id_validators, 0, sizeof(consensus_state.id_validators));
            }

            continue;
        }
    }

    return NULL;
}

