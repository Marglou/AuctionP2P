/*
 * Ce fichier contient le point d'entrée principal du programme pair.
 * Il :
 *  - demande à l'utilisateur de saisir un nom pour le pair via l'entrée standard,
 *  - lit ce nom tout en supprimant le caractère de fin de ligne éventuel ('\n'),
 *  - initialise le pair en appelant la fonction `peer_start` avec le nom fourni.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/peer.h"

int main() {

    char nom[100];  // Déclaration du tableau pour le nom du pair

    // Demander le nom de l'utilisateur
    printf("Nom du pair : ");
    fflush(stdout);  // Assurer que le message est bien affiché avant la lecture de l'entrée

    // Lire l'entrée de l'utilisateur
    fgets(nom, sizeof(nom), stdin); 

    // Enlever le caractère de nouvelle ligne '\n' si présent
    nom[strcspn(nom, "\n")] = '\0';

    peer_start(nom);

    return 0;
}
