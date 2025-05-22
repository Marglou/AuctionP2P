#include "../include/udp_response.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "../include/peer.h"

void init_udp_response_manager(struct udp_response_manager* manager) {
    manager->pending_messages = malloc(sizeof(struct udp_message_status) * MAX_PENDING_MESSAGES);
    manager->num_pending = 0;
    manager->max_pending = MAX_PENDING_MESSAGES;
    printf("[UDP Response] Initialized UDP response manager with capacity for %d pending messages\n", MAX_PENDING_MESSAGES);
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
        printf("[UDP Response] Warning: Cannot track new message - maximum pending messages reached\n");
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
    new_msg->response_received = false;


    printf("[UDP Response] Tracking new message: code=%d, peer_id=%d, length=%zu\n", 
           code, peer_id, message_len);
    return 0;
}

void mark_response_received(struct udp_response_manager* manager, uint8_t code, uint16_t peer_id) {
    for (int i = 0; i < manager->num_pending; i++) {
        struct udp_message_status* msg = &manager->pending_messages[i];
        if (msg->message_code == code && msg->target_peer_id == peer_id) {
            msg->response_received = true;
            printf("[UDP Response] Response received for message: code=%d, peer_id=%d\n", code, peer_id);
            return;
        }
    }
    printf("[UDP Response] Warning: Received response for untracked message: code=%d, peer_id=%d\n", 
           code, peer_id);
}

void check_and_retry_messages(struct udp_response_manager* manager) {
    time_t current_time = time(NULL);
    
    for (int i = 0; i < manager->num_pending; i++) {
        struct udp_message_status* msg = &manager->pending_messages[i];
        
        // Skip if response already received
        if (msg->response_received) {
            continue;
        }

        // Check if we need to retry
        if (current_time - msg->send_time >= RETRY_TIMEOUT_SEC) {
            if (msg->retry_count < MAX_RETRIES) {
                printf("[UDP Response] Retrying message: code=%d, peer_id=%d, attempt=%d/%d\n",
                       msg->message_code, msg->target_peer_id, msg->retry_count + 1, MAX_RETRIES);
                
                struct sockaddr_in6 peer_addr = {0};
                peer_addr.sin6_family = AF_INET6;
                peer_addr.sin6_port = htons(p.discovered_peers[msg->target_peer_id].port_tcp);
                memcpy(&peer_addr.sin6_addr, &p.discovered_peers[msg->target_peer_id].ip, sizeof(struct in6_addr));
                peer_addr.sin6_scope_id = p.global_iface_index;

                if (sendto(p.socket_udp, msg->message_data, msg->message_len, 0,
                          (struct sockaddr*)&peer_addr,
                          sizeof(struct sockaddr_in6)) < 0) {
                    perror("Error retrying UDP message");
                    continue;
                }
                
                msg->retry_count++;
                msg->send_time = current_time;
                printf("Retrying message code %d to peer %d (attempt %d/%d)\n",
                       msg->message_code, msg->target_peer_id,
                       msg->retry_count, MAX_RETRIES);
            } else {
                // Max retries reached, remove the message
                printf("Max retries reached for message code %d to peer %d\n",
                       msg->message_code, msg->target_peer_id);
                remove_completed_message(manager, msg->message_code, msg->target_peer_id);
                i--; // Adjust index since we removed an element
            }
        }
    }
}

void remove_completed_message(struct udp_response_manager* manager, uint8_t code, uint16_t peer_id) {
    for (int i = 0; i < manager->num_pending; i++) {
        struct udp_message_status* msg = &manager->pending_messages[i];
        if (msg->message_code == code && msg->target_peer_id == peer_id) {
            printf("[UDP Response] Removing completed message: code=%d, peer_id=%d\n", code, peer_id);
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