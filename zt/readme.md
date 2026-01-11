Mettre à jour et installer Python3 :
sudo apt update
sudo apt install -y python3 python3-venv python3-pip python3-dev libxml2-dev libxslt-dev zlib1g-dev

Créer un environnement virtuel Python : 
python3 -m venv ryu-venv
source ryu-venv/bin/activate

Mettre à jour pip et setuptools et wheel et eventlet et matplotlib:
pip install --upgrade pip setuptools wheel
pip install 'eventlet==0.30.2'
pip install matplotlib

Installer Ryu :
pip install ryu

Executer le fichier Zero_Trust.py :

ruy-manager Zero_Trust.py

Executer le fichier topoology.py dans un autre terminal :
python3 topoology.py

Executer le fichier metriques.py dans un autre terminal :
python3 metriques.py




