#ifndef PEER_H
#define PEER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/socket.h>

void peer_start(const char *nom, const char *interface);
void start_auction(const char *nom, const char *interface);
#endif
