#ifndef CONNEXION_H
#define CONNEXION_H

int connexion_TLS (struct in6_addr ip, uint16_t port);
// SSL *connexion_TLS(struct in6_addr ip, uint16_t port);
int connexion_TCP (struct in6_addr ip, uint16_t port);

#endif 