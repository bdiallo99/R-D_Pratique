# R-D_Pratique
# Présentation du projet

Ce projet illustre une implémentation pratique du modèle Zero Trust Networking à l’aide du Software-Defined Networking (SDN).
L’objectif est de démontrer qu’un réseau peut adapter dynamiquement ses règles d’accès en fonction du comportement des utilisateurs, jusqu’à révoquer un accès en cours de session lorsqu’une activité devient suspecte.

L’approche repose sur un contrôleur SDN capable de surveiller les flux réseau et de modifier les règles OpenFlow en temps réel.

# Objectifs principaux

La maquette met en évidence les concepts clés du Zero Trust :

Micro-segmentation du réseau

Surveillance continue des flux

Révocation dynamique des accès

Contrôle d’accès piloté par logiciel

Architecture de la maquette

La topologie est volontairement simple et simulée avec Mininet :

1 contrôleur SDN basé sur Ryu

1 switch OpenFlow (Open vSwitch)

4 hôtes :

h1 : utilisateur normal

h2 : utilisateur suspect

h3 : serveur de ressources

h4 : serveur de remédiation

Tous les hôtes sont connectés au même switch, contrôlé à distance par Ryu.

Environnement requis
Système

Ubuntu 22.04 LTS

Déploiement possible sur machine physique, VM ou WSL2 (avec limitations)

Ressources recommandées

CPU : 4 cœurs minimum

RAM : 8 Go (16 Go recommandé)

Disque : ≥ 30 Go

Outils SDN et réseau

Mininet : simulation de la topologie réseau

Open vSwitch (OVS) : switch OpenFlow

Ryu : contrôleur SDN en Python

Environnement logiciel

Python 3.10+

# Bibliothèques principales :

ryu

flask (API de décision)

requests

Outils réseau standards : iproute2, tcpdump, nmap

Organisation du projet

Le projet repose sur deux fichiers principaux :

zero_trust.py
→ Application Ryu jouant initialement le rôle d’un switch L2 apprenant, base pour l’ajout de la logique Zero Trust.

topo.py
→ Définition de la topologie Mininet (1 switch, 4 hôtes, connexion au contrôleur).

# Principe de fonctionnement

Le contrôleur Ryu installe une règle table-miss à la connexion du switch.

Chaque paquet inconnu est envoyé au contrôleur.

Le contrôleur apprend dynamiquement les adresses MAC et installe des règles OpenFlow.

Les flux légitimes sont autorisés automatiquement.

Le modèle est conçu pour évoluer vers :

l’analyse de comportement,

la détection d’activité suspecte,

la révocation immédiate des accès réseau.

Validation de la maquette

La maquette est validée par :

des tests de connectivité (ping) entre hôtes,

des tests de trafic HTTP,

la vérification des flows OpenFlow installés sur le switch.

## Segmentation dynamique (Ryu / OpenFlow 1.3)

Ce module `segmentation_dynamique.py` implémente une micro-segmentation “Zero Trust” sur un switch Open vSwitch contrôlé par Ryu.

**Règles appliquées :**
- **h4 est totalement isolé** (ARP + IPv4 bloqués dès qu’il est source ou destination)
- **ICMP (ping) autorisé uniquement entre h1, h2 et h3**
- **HTTP/HTTPS autorisé de h1/h2 vers h3** (ports 80 et 443) + réponses de h3 vers h1/h2
- Tout le reste est refusé par défaut

**Fonctionnement :**
- Le contrôleur apprend les ports via **MAC learning**
- Les flux autorisés sont ensuite installés dynamiquement dans le switch pour éviter de repasser au contrôleur à chaque paquet

**Lancement :**
```bash
ryu-manager segmentation_dynamique.py

Monitoring (Étape 3) 

** Nettoyer OVS/Mininet : sudo mn -c

** Lancer le contrôleur avec télémétrie (dans ~/projet) :**
ryu-manager segmentation_dynamique_telemetrie.py

**Lancer la topologie (autre terminal) :**
sudo python3 topo.py

Vérifier que le switch reçoit des flows :
sudo ovs-ofctl -O OpenFlow13 dump-flows s1

Test ping autorisé (dans Mininet CLI) : h1 ping -c 3 h2
→ tu dois voir des logs [FLOW-STATS] ... packets/bytes côté contrôleur.

Lancer un serveur HTTP sur h3 : h3 python3 -m http.server 80

HTTP autorisé depuis h1/h2 : h1 curl -I http://10.0.0.3 et h2 curl -I http://10.0.0.3

HTTP interdit depuis h4 : h4 curl -I http://10.0.0.3
→ le contrôleur affiche DROP ...

**Simuler un scan de ports depuis h1 :**
h1 bash -c 'for p in $(seq 1 30); do timeout 0.2 bash -c "echo >/dev/tcp/10.0.0.3/$p" 2>/dev/null; done'

Résultat attendu : logs [SCAN?] src=10.0.0.1 tried X unique TCP dst ports... + DROP IPv4 ... proto=6 pour les ports non autorisés.
