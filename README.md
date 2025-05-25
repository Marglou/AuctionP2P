# AuctionP2P - Système d'enchères P2P

Un système d'enchères pair-à-pair implémenté en C qui permet aux utilisateurs de créer et de participer à des enchères sur un réseau.

## Construction du projet

1. Clonez le dépôt :
```bash
git clone https://moule.informatique.univ-paris-diderot.fr/popovic/auctionp2p.git
cd auctionp2p
```

2. Exécution :
```bash
make run
```

## Test du système

1. Ouvrez plusieurs terminaux pour simuler différents homologues.

2. Dans chaque terminal, exécutez le programme :
```bash
make run 
```

Une fois le programme lancé, il vous sera demandé :

1. Un pseudo pour le pair
2. Un solde pour le pair
3. Un numéro de port (valide et non utilisé) pour l'écoute
Chaque pair peut être lancé dans un terminal différent pour simuler plusieurs participants.

## Nettoyage

Pour nettoyer les fichiers de build :
```bash
make clean
```

## Commandes interactives (clavier)
    
Crée une nouvelle enchère et devient superviseur de la vente.
```bash
lancer
```
Tente de rejoindre une enchère existante via le multicast.
```bash
join
```
Lance une vente sur une enchère existante si vous êtes superviseur.
```bash
vente
```
Surenchérit lors d'une vente en cours.  
```bash
offre
```
Affiche la liste des enchères connues et actives.
```bash
encheres
``` 
Quitte l'enchère active et/ou termine le programme.
```bash
quit
```
Affiche l'aide des commandes.
```bash
help
``` 
## Comportement du protocole

- Lancement d'une enchère : via lancer, un message est multidiffusé et le pair devient superviseur.
- Rejoindre une enchère : en cas de non-réponse, 3 tentatives sont faites avant de créer une nouvelle enchère automatiquement.
- Consensus : Chaque message sensible (offre, fin de vente, etc.) est validé par signature ED25519 entre pairs.
- Vente : Une fois lancée, les pairs peuvent proposer des prix. Le superviseur valide et multidiffuse chaque offre acceptée.
- Fin de vente : Si aucun nouveau prix n'est reçu dans un délai donné, la vente se termine et un message de victoire est émis.
- Quitter : Quitte proprement la vente et informe les pairs via multicast.

## Arborescence du projet
```bash
AuctionP2P/
├── include/                # Fichiers d'en-tête (.h)
│   ├── connexion.h
│   ├── enchere.h
│   ├── message.h
│   ├── peer.h
│   ├── securite.h
│   ├── superviseur.h
│   ├── udp_response.h
│   └── utils.h
│
├── src/                    # Fichiers source (.c)
│   ├── connexion.c
│   ├── enchere.c
│   ├── main.c
│   ├── message.c
│   ├── peer.c
│   ├── securite.c
│   ├── superviseur.c
│   ├── udp_response.c
│   └── utils.c
│
├── Makefile                # Script de compilation
├── README.md               # Documentation utilisateur
└── authors.md              # Informations sur les auteurs
```
