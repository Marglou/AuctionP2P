// superviseur.c
#include "../include/peer.h"
#include "../include/superviseur.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>  // pour mkdir
#include <sys/types.h> // optionnel, mais recommandé avec mkdir
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

