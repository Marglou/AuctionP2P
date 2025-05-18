#ifndef CONNEXION_H
#define CONNEXION_H


void *listen_adrPerso_thread(void *arg);
int connexion_TLS(struct in6_addr ip, uint16_t port);
int gestion_socket ();


#endif // CONNEXION_H