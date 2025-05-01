# AuctionP2P - Système d'enchères P2P

Un système d'enchères pair-à-pair implémenté en C qui permet aux utilisateurs de créer et de participer à des enchères sur un réseau.

```
## Construction du projet

1. Clonez le dépôt :
```bash
git clone https://moule.informatique.univ-paris-diderot.fr/popovic/auctionp2p.git
cd auctionp2p
```

2. Construisez le projet :
```bash
make
```

## Test du système

### Tests de base

1. Ouvrez plusieurs terminaux pour simuler différents homologues.

2. Dans chaque terminal, exécutez le programme :
```bash
./enchere
```

3. Lorsque vous y êtes invité, saisissez un nom unique pour chaque homologue.

### Scénarios de test

#### Scénario 1 : Créer une enchère
1. Dans le terminal du premier pair, saisissez :
```
lancer
```
Une nouvelle enchère sera créée.

#### Scénario 2 : Rejoindre une enchère
1. Dans le terminal d’un autre pair, saisissez :
```
join
```
Une tentative de rejoindre une enchère existante sera effectuée.

#### Scénario 3 : Communication
1. Une fois connecté à une enchère, vous pouvez saisir des messages qui seront diffusés à tous les pairs participants.

### Interface réseau

Le système utilise l’interface réseau spécifiée dans le code. Par défaut, elle est définie sur « enp0s3 ». Si vous utilisez une autre interface, modifiez le nom de l’interface dans `src/main.c` :

```c
peer_start(nom, "your_interface_name"); ```

Noms d'interface courants :
- Linux : « eth0 », « wlan0 »
- macOS : « en0 »
- Windows : « Ethernet », « Wi-Fi »

## Notes de sécurité

- Le système utilise TLS pour sécuriser les communications.
- Chaque homologue possède une paire de clés ED25519 unique.
- Les messages sont signés pour garantir leur authenticité.
- Soyez prudent lors des tests sur les réseaux publics.

## Nettoyage

Pour nettoyer les fichiers de build :
```bash
make clean
```