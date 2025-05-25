/*
 * Ce module gère le suivi des messages UDP envoyés aux pairs,
 * leur retransmission en cas d'absence d'accusé de réception,
 * et la détection des pairs absents après plusieurs tentatives.
*/

#include "../include/udp_response.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "../include/peer.h"
#include "../include/enchere.h"

void init_udp_response_manager(struct udp_response_manager* manager) {
    manager->pending_messages = malloc(sizeof(struct udp_message_status) * MAX_PENDING_MESSAGES);
    manager->num_pending = 0;
    manager->max_pending = MAX_PENDING_MESSAGES;
}

void cleanup_udp_response_manager(struct udp_response_manager* manager) {
    for (int i = 0; i < manager->num_pending; i++) {
        free(manager->pending_messages[i].message_data);
    }
    free(manager->pending_messages);
    manager->num_pending = 0;
    manager->max_pending = 0;
}

int track_udp_message(struct udp_response_manager* manager, uint8_t code, uint16_t peer_id, 
                     void* message_data, size_t message_len) {
    if (manager->num_pending >= manager->max_pending) {
        return -1;
    }

    struct udp_message_status* new_msg = &manager->pending_messages[manager->num_pending++];
    new_msg->message_code = code;
    new_msg->target_peer_id = peer_id;
    new_msg->message_data = malloc(message_len);
    memcpy(new_msg->message_data, message_data, message_len);
    new_msg->message_len = message_len;
    new_msg->send_time = time(NULL);
    new_msg->retry_count = 0;
    new_msg->completed = false;
    return 0;
}

void mark_response_received(struct udp_response_manager* manager, uint8_t code, uint16_t peer_id) {
    for (int i = 0; i < manager->num_pending; i++) {
        struct udp_message_status* msg = &manager->pending_messages[i];
        if (msg->message_code == code && msg->target_peer_id == peer_id) {
            msg->completed = true;
            return;
        }
    }
}

void check_and_retry_messages(struct udp_response_manager* manager) {
    time_t current_time = time(NULL);
    uint16_t absent_peers[MAX_PEERS];
    uint16_t num_absent = 0;

    for (int i = 0; i < manager->num_pending; i++) {
        struct udp_message_status* msg = &manager->pending_messages[i];
        
        if (msg->completed) continue;
        
        if (msg->retry_count >= MAX_RETRIES) {
            
            bool already_listed = false;
            for (int j = 0; j < num_absent; j++) {
                if (absent_peers[j] == msg->target_peer_id) {
                    already_listed = true;
                    break;
                }
            }
            if (!already_listed && num_absent < MAX_PEERS) {
                absent_peers[num_absent++] = msg->target_peer_id;
            }
            continue;
        }
        
        if (current_time - msg->last_sent_time >= RETRY_TIMEOUT_SEC) {
           
            struct sockaddr_in6 peer_addr = {0};
            peer_addr.sin6_family = AF_INET6;
            peer_addr.sin6_port = htons(p.port_perso);
            memcpy(&peer_addr.sin6_addr, &p.discovered_peers[msg->target_peer_id].ip, sizeof(struct in6_addr));
            
            if (sendto(p.socket_udp, msg->message_data, msg->message_len, 0,
                      (struct sockaddr*)&peer_addr,
                      sizeof(struct sockaddr_in6)) < 0) {
                perror("sendto in check_and_retry_messages");
            } else {
                msg->last_sent_time = current_time;
                msg->retry_count++;
            }
        }
    }

    // Handle absent peers if any
    if (num_absent > 0) {
        handle_peer_disappearance(absent_peers, num_absent);
        
        // Remove completed messages for absent peers
        for (int i = 0; i < num_absent; i++) {
            remove_completed_message(manager, 1, absent_peers[i]);
        }
    }
}

void remove_completed_message(struct udp_response_manager* manager, uint8_t code, uint16_t peer_id) {
    for (int i = 0; i < manager->num_pending; i++) {
        struct udp_message_status* msg = &manager->pending_messages[i];
        if (msg->message_code == code && msg->target_peer_id == peer_id) {
            free(msg->message_data);
            // Move the last message to this position
            if (i < manager->num_pending - 1) {
                memcpy(msg, &manager->pending_messages[manager->num_pending - 1], 
                       sizeof(struct udp_message_status));
            }
            manager->num_pending--;
            return;
        }
    }
} 