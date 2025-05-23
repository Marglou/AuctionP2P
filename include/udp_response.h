#ifndef UDP_RESPONSE_H
#define UDP_RESPONSE_H

#include <stdbool.h>
#include <time.h>
#include <stdint.h>

#define MAX_RETRIES 2
#define RETRY_TIMEOUT_SEC 5
#define RESPONSE_TIMEOUT_SEC 5
#define MAX_PENDING_MESSAGES 100  // Maximum number of pending messages to track

// Structure to track UDP message status
struct udp_message_status {
    uint8_t message_code;
    uint16_t target_peer_id;
    void* message_data;
    size_t message_len;
    time_t last_sent_time;
    time_t send_time;
    int retry_count;
    bool completed;
};

// UDP response manager structure
struct udp_response_manager {
    struct udp_message_status* pending_messages;
    int num_pending;
    int max_pending;
};

// Function declarations
void init_udp_response_manager(struct udp_response_manager* manager);
void cleanup_udp_response_manager(struct udp_response_manager* manager);
int track_udp_message(struct udp_response_manager* manager, uint8_t code, uint16_t peer_id, 
                     void* message_data, size_t message_len);
void mark_response_received(struct udp_response_manager* manager, uint8_t code, uint16_t peer_id);
void check_and_retry_messages(struct udp_response_manager* manager);
void remove_completed_message(struct udp_response_manager* manager, uint8_t code, uint16_t peer_id);

#endif // UDP_RESPONSE_H 