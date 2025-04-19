#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include_2/peer.h"

int main() {
    char nom[100];
    printf("Nom du pair : ");
    fflush(stdout);
    fgets(nom, sizeof(nom), stdin);
    nom[strcspn(nom, "\n")] = '\0';  // Enlève le \n

    // peer_start(nom, "en0");  // Pour MAC
    peer_start(nom, "eth0");  // Pour PC
    return 0;
}
