
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time


def create_zerotrust_topology():
    """
    Création d'une topologie réseau minimaliste pour tester Zero Trust
    
    Topologie :
    - 1 switch OpenFlow (s1)
    - 4 hôtes avec différents rôles :
        * h1 (alice) : admin
        * h2 (bob) : user
        * h3 (charlie) : user
        * h4 (dave) : guest
    - 1 serveur (h5) : serveur web/base de données
    """
    
    info("*** Création du réseau Zero Trust\n")
    
    # Création du réseau avec contrôleur distant (Ryu)
    net = Mininet(
        controller=RemoteController,
        switch=OVSKernelSwitch,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=True
    )
    
    info("*** Ajout du contrôleur Ryu\n")
    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6653
    )
    
    info("*** Ajout du switch OpenFlow\n")
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    
    info("*** Ajout des hôtes\n")
    
    # Hôte 1 : Alice (admin) - MAC: 00:00:00:00:00:01
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    
    # Hôte 2 : Bob (user) - MAC: 00:00:00:00:00:02
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    
    # Hôte 3 : Charlie (user) - MAC: 00:00:00:00:00:03
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
    
    # Hôte 4 : Dave (guest) - MAC: 00:00:00:00:00:04
    h4 = net.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')
    
    # Hôte 5 : Serveur - MAC: 00:00:00:00:00:05
    h5 = net.addHost('h5', ip='10.0.0.5/24', mac='00:00:00:00:00:05')
    
    info("*** Création des liens\n")
    # Liens avec limitation de bande passante pour simulation réaliste
    net.addLink(h1, s1, bw=10)  # 10 Mbps
    net.addLink(h2, s1, bw=10)
    net.addLink(h3, s1, bw=10)
    net.addLink(h4, s1, bw=5)   # Guest : bande passante limitée
    net.addLink(h5, s1, bw=100) # Serveur : haute bande passante
    
    info("*** Démarrage du réseau\n")
    net.build()
    c0.start()
    s1.start([c0])
    
    info("*** Configuration des services sur le serveur\n")
    # Serveur web sur le port 80
    h5.cmd('python3 -m http.server 80 &> /tmp/http_server.log &')
    
    # Serveur SSH simulé sur le port 22
    h5.cmd('nc -l -p 22 &> /tmp/ssh_server.log &')
    
    # Serveur MySQL simulé sur le port 3306
    h5.cmd('nc -l -p 3306 &> /tmp/mysql_server.log &')
    
    info("*** Réseau Zero Trust prêt\n")
    info("*** Hôtes configurés :\n")
    info("    h1 (alice - admin)   : 10.0.0.1 [MAC: 00:00:00:00:00:01]\n")
    info("    h2 (bob - user)      : 10.0.0.2 [MAC: 00:00:00:00:00:02]\n")
    info("    h3 (charlie - user)  : 10.0.0.3 [MAC: 00:00:00:00:00:03]\n")
    info("    h4 (dave - guest)    : 10.0.0.4 [MAC: 00:00:00:00:00:04]\n")
    info("    h5 (serveur)         : 10.0.0.5 [MAC: 00:00:00:00:00:05]\n")
    info("\n")
    
    return net


def run_topology():
    """Lance la topologie et ouvre le CLI Mininet"""
    setLogLevel('info')
    
    net = create_zerotrust_topology()
    
    info("*** Attente de la connexion au contrôleur Ryu (5 secondes)...\n")
    time.sleep(5)
    
    info("\n=== Topologie Zero Trust active ===\n")
    info("Commandes utiles :\n")
    info("  - pingall : tester la connectivité\n")
    info("  - h1 ping h5 : ping depuis alice vers le serveur\n")
    info("  - xterm h1 : ouvrir un terminal pour h1\n")
    info("  - Ctrl+D ou 'exit' : quitter\n\n")
    
    CLI(net)
    
    info("*** Arrêt du réseau\n")
    net.stop()


if __name__ == '__main__':
    run_topology()




