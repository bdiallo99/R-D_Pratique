
import json
import time
import subprocess
import statistics
from datetime import datetime
from collections import defaultdict
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np


class PerformanceMetrics:
    """Classe pour collecter et analyser les métriques de performance"""
    
    def __init__(self):
        self.metrics = {
            'revocation_times': [],
            'detection_accuracies': [],
            'false_positives': 0,
            'false_negatives': 0,
            'true_positives': 0,
            'true_negatives': 0,
            'throughput_measurements': [],
            'latency_measurements': [],
            'controller_overhead': [],
            'flow_rule_counts': []
        }
        
        self.start_time = None
        self.end_time = None
    
    def start_measurement(self):
        """Démarre la mesure"""
        self.start_time = time.time()
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Demarrage des mesures de performance")
    
    def stop_measurement(self):
        """Arrête la mesure"""
        self.end_time = time.time()
        duration = self.end_time - self.start_time
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Fin des mesures (duree: {duration:.2f}s)")
    
    def measure_revocation_time(self, detection_time, revocation_complete_time):
        """
        Mesure le temps entre la détection et la révocation complète
        
        Args:
            detection_time: timestamp de détection de l'anomalie
            revocation_complete_time: timestamp de révocation complète
        """
        revocation_time = revocation_complete_time - detection_time
        self.metrics['revocation_times'].append(revocation_time)
        print(f" Temps de revocation: {revocation_time*1000:.2f} ms")
        return revocation_time
    
    def record_detection(self, is_attack, detected_as_attack):
        """
        Enregistre une détection pour calculer la précision
        
        Args:
            is_attack: True si c'était réellement une attaque
            detected_as_attack: True si détecté comme attaque
        """
        if is_attack and detected_as_attack:
            self.metrics['true_positives'] += 1
        elif is_attack and not detected_as_attack:
            self.metrics['false_negatives'] += 1
        elif not is_attack and detected_as_attack:
            self.metrics['false_positives'] += 1
        else:
            self.metrics['true_negatives'] += 1
    
    def measure_throughput(self, bytes_transferred, duration):
        """
        Mesure le débit réseau
        
        Args:
            bytes_transferred: nombre d'octets transférés
            duration: durée du transfert (secondes)
        """
        if duration > 0:
            throughput_mbps = (bytes_transferred * 8) / (duration * 1_000_000)
            self.metrics['throughput_measurements'].append(throughput_mbps)
            return throughput_mbps
        return 0
    
    def measure_latency(self, latency_ms):
        """
        Enregistre une mesure de latence
        
        Args:
            latency_ms: latence en millisecondes
        """
        self.metrics['latency_measurements'].append(latency_ms)
    
    def measure_controller_overhead(self, cpu_percent, memory_mb):
        """
        Mesure l'overhead du contrôleur
        
        Args:
            cpu_percent: utilisation CPU en %
            memory_mb: utilisation mémoire en MB
        """
        self.metrics['controller_overhead'].append({
            'cpu': cpu_percent,
            'memory': memory_mb,
            'timestamp': time.time()
        })
    
    def calculate_accuracy(self):
        """Calcule la précision de détection"""
        tp = self.metrics['true_positives']
        tn = self.metrics['true_negatives']
        fp = self.metrics['false_positives']
        fn = self.metrics['false_negatives']
        
        total = tp + tn + fp + fn
        if total == 0:
            return 0
        
        accuracy = (tp + tn) / total
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'true_positives': tp,
            'true_negatives': tn,
            'false_positives': fp,
            'false_negatives': fn
        }
    
    def generate_report(self):
        """Génère un rapport complet des métriques"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'measurement_duration': self.end_time - self.start_time if self.end_time else 0,
            'revocation_metrics': {},
            'detection_metrics': {},
            'performance_metrics': {},
            'controller_metrics': {}
        }
        
        # Métriques de révocation
        if self.metrics['revocation_times']:
            report['revocation_metrics'] = {
                'mean_time_ms': statistics.mean(self.metrics['revocation_times']) * 1000,
                'median_time_ms': statistics.median(self.metrics['revocation_times']) * 1000,
                'min_time_ms': min(self.metrics['revocation_times']) * 1000,
                'max_time_ms': max(self.metrics['revocation_times']) * 1000,
                'std_dev_ms': statistics.stdev(self.metrics['revocation_times']) * 1000 if len(self.metrics['revocation_times']) > 1 else 0,
                'count': len(self.metrics['revocation_times'])
            }
        
        # Métriques de détection
        report['detection_metrics'] = self.calculate_accuracy()
        
        # Métriques de performance réseau
        if self.metrics['throughput_measurements']:
            report['performance_metrics']['throughput'] = {
                'mean_mbps': statistics.mean(self.metrics['throughput_measurements']),
                'median_mbps': statistics.median(self.metrics['throughput_measurements']),
                'min_mbps': min(self.metrics['throughput_measurements']),
                'max_mbps': max(self.metrics['throughput_measurements'])
            }
        
        if self.metrics['latency_measurements']:
            report['performance_metrics']['latency'] = {
                'mean_ms': statistics.mean(self.metrics['latency_measurements']),
                'median_ms': statistics.median(self.metrics['latency_measurements']),
                'min_ms': min(self.metrics['latency_measurements']),
                'max_ms': max(self.metrics['latency_measurements']),
                'p95_ms': np.percentile(self.metrics['latency_measurements'], 95),
                'p99_ms': np.percentile(self.metrics['latency_measurements'], 99)
            }
        
        # Métriques du contrôleur
        if self.metrics['controller_overhead']:
            cpu_values = [m['cpu'] for m in self.metrics['controller_overhead']]
            memory_values = [m['memory'] for m in self.metrics['controller_overhead']]
            
            report['controller_metrics'] = {
                'cpu_usage': {
                    'mean_percent': statistics.mean(cpu_values),
                    'max_percent': max(cpu_values)
                },
                'memory_usage': {
                    'mean_mb': statistics.mean(memory_values),
                    'max_mb': max(memory_values)
                }
            }
        
        return report
    
    def save_report(self, filename='metriques/performance_report.json'):
        """Sauvegarde le rapport en JSON"""
        report = self.generate_report()
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"Rapport sauvegarde : {filename}")
        return filename
    
    def plot_metrics(self, output_dir='metriques'):
        """Génère des graphiques de visualisation"""
        
        # Graphique 1 : Temps de révocation
        if self.metrics['revocation_times']:
            plt.figure(figsize=(10, 6))
            plt.plot(self.metrics['revocation_times'], marker='o')
            plt.title('Temps de Revocation par Incident', fontsize=14, fontweight='bold')
            plt.xlabel('Incident #')
            plt.ylabel('Temps (secondes)')
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            plt.savefig(f'{output_dir}/revocation_times.png', dpi=300)
            plt.close()
            print(f"Graphique sauvegarde : {output_dir}/revocation_times.png")
        
        # Graphique 2 : Matrice de confusion
        accuracy_data = self.calculate_accuracy()
        if accuracy_data['true_positives'] + accuracy_data['false_positives'] > 0:
            fig, ax = plt.subplots(figsize=(8, 6))
            
            confusion_matrix = np.array([
                [accuracy_data['true_positives'], accuracy_data['false_positives']],
                [accuracy_data['false_negatives'], accuracy_data['true_negatives']]
            ])
            
            im = ax.imshow(confusion_matrix, cmap='Blues')
            
            ax.set_xticks([0, 1])
            ax.set_yticks([0, 1])
            ax.set_xticklabels(['Attaque Predite', 'Normal Predit'])
            ax.set_yticklabels(['Attaque Reelle', 'Normal Reel'])
            
            # Annotations
            for i in range(2):
                for j in range(2):
                    text = ax.text(j, i, confusion_matrix[i, j],
                                   ha="center", va="center", color="black", fontsize=20)
            
            ax.set_title('Matrice de Confusion - Detection des Attaques', fontsize=14, fontweight='bold')
            plt.colorbar(im, ax=ax)
            plt.tight_layout()
            plt.savefig(f'{output_dir}/confusion_matrix.png', dpi=300)
            plt.close()
            print(f"Graphique sauvegarde : {output_dir}/confusion_matrix.png")
        
        # Graphique 3 : Métriques de performance
        if self.metrics['throughput_measurements'] and self.metrics['latency_measurements']:
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
            
            # Throughput
            ax1.hist(self.metrics['throughput_measurements'], bins=20, color='green', alpha=0.7)
            ax1.set_title('Distribution du Debit', fontweight='bold')
            ax1.set_xlabel('Debit (Mbps)')
            ax1.set_ylabel('Frequence')
            ax1.grid(True, alpha=0.3)
            
            # Latence
            ax2.hist(self.metrics['latency_measurements'], bins=20, color='orange', alpha=0.7)
            ax2.set_title('Distribution de la Latence', fontweight='bold')
            ax2.set_xlabel('Latence (ms)')
            ax2.set_ylabel('Frequence')
            ax2.grid(True, alpha=0.3)
            
            plt.tight_layout()
            plt.savefig(f'{output_dir}/performance_distributions.png', dpi=300)
            plt.close()
            print(f"Graphique sauvegarde : {output_dir}/performance_distributions.png")
        
        # Graphique 4 : Overhead du contrôleur
        if self.metrics['controller_overhead']:
            fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8))
            
            timestamps = [m['timestamp'] - self.metrics['controller_overhead'][0]['timestamp'] 
                          for m in self.metrics['controller_overhead']]
            cpu_values = [m['cpu'] for m in self.metrics['controller_overhead']]
            memory_values = [m['memory'] for m in self.metrics['controller_overhead']]
            
            # CPU
            ax1.plot(timestamps, cpu_values, color='red', linewidth=2)
            ax1.set_title('Utilisation CPU du Controleur', fontweight='bold')
            ax1.set_xlabel('Temps (s)')
            ax1.set_ylabel('CPU (%)')
            ax1.grid(True, alpha=0.3)
            
            # Mémoire
            ax2.plot(timestamps, memory_values, color='blue', linewidth=2)
            ax2.set_title('Utilisation Mémoire du Controleur', fontweight='bold')
            ax2.set_xlabel('Temps (s)')
            ax2.set_ylabel('Memoire (MB)')
            ax2.grid(True, alpha=0.3)
            
            plt.tight_layout()
            plt.savefig(f'{output_dir}/controller_overhead.png', dpi=300)
            plt.close()
            print(f" Graphique sauvegarde : {output_dir}/controller_overhead.png")
    
    def print_summary(self):
        """Affiche un résumé des métriques"""
        report = self.generate_report()
        
        print("\n" + "=" * 80)
        print("RESUME DES METRIQUES DE PERFORMANCE")
        print("=" * 80)
        
        # Métriques de révocation
        if 'revocation_metrics' in report and report['revocation_metrics']:
            print("\n METRIQUES DE REVOCATION")
            print("-" * 80)
            rm = report['revocation_metrics']
            print(f"  Temps moyen de révocation    : {rm['mean_time_ms']:.2f} ms")
            print(f"  Temps médian de révocation   : {rm['median_time_ms']:.2f} ms")
            print(f"  Temps minimum                : {rm['min_time_ms']:.2f} ms")
            print(f"  Temps maximum                : {rm['max_time_ms']:.2f} ms")
            print(f"  Écart-type                   : {rm['std_dev_ms']:.2f} ms")
            print(f"  Nombre de révocations        : {rm['count']}")
        
        # Métriques de détection
        if 'detection_metrics' in report:
            print("\n METRIQUES DE DETECTION")
            print("-" * 80)
            dm = report['detection_metrics']
            print(f"  Precision (Accuracy)         : {dm['accuracy']*100:.2f}%")
            print(f"  Precision (Precision)        : {dm['precision']*100:.2f}%")
            print(f"  Rappel (Recall)              : {dm['recall']*100:.2f}%")
            print(f"  Score F1                     : {dm['f1_score']:.4f}")
            print(f"  Vrais positifs               : {dm['true_positives']}")
            print(f"  Vrais négatifs               : {dm['true_negatives']}")
            print(f"  Faux positifs                : {dm['false_positives']}")
            print(f"  Faux négatifs                : {dm['false_negatives']}")
        
        # Métriques de performance
        if 'performance_metrics' in report and report['performance_metrics']:
            print("\n METRIQUES DE PERFORMANCE RESEAU")
            print("-" * 80)
            pm = report['performance_metrics']
            
            if 'throughput' in pm:
                print(f"  Debit moyen                  : {pm['throughput']['mean_mbps']:.2f} Mbps")
                print(f"  Debit median                 : {pm['throughput']['median_mbps']:.2f} Mbps")
            
            if 'latency' in pm:
                print(f"  Latence moyenne              : {pm['latency']['mean_ms']:.2f} ms")
                print(f"  Latence mediane              : {pm['latency']['median_ms']:.2f} ms")
                print(f"  Latence P95                  : {pm['latency']['p95_ms']:.2f} ms")
                print(f"  Latence P99                  : {pm['latency']['p99_ms']:.2f} ms")
        
        # Métriques du contrôleur
        if 'controller_metrics' in report and report['controller_metrics']:
            print("\n  METRIQUES DU CONTROLEUR")
            print("-" * 80)
            cm = report['controller_metrics']
            
            if 'cpu_usage' in cm:
                print(f"  CPU moyen                    : {cm['cpu_usage']['mean_percent']:.2f}%")
                print(f"  CPU maximum                  : {cm['cpu_usage']['max_percent']:.2f}%")
            
            if 'memory_usage' in cm:
                print(f"  Mémoire moyenne              : {cm['memory_usage']['mean_mb']:.2f} MB")
                print(f"  Mémoire maximum              : {cm['memory_usage']['max_mb']:.2f} MB")
        
        print("\n" + "=" * 80)


def simulate_performance_test():
    """Simulation de test de performance pour démonstration"""
    
    metrics = PerformanceMetrics()
    metrics.start_measurement()
    
    print("\n Simulation de tests de performance...")
    
    # Simulation de révocations
    print("\n 1  Test des temps de revocation...")
    for i in range(10):
        detection_time = time.time()
        time.sleep(0.01 + np.random.random() * 0.05)  # Simulation
        revocation_time = time.time()
        metrics.measure_revocation_time(detection_time, revocation_time)
    
    # Simulation de détections
    print("\n 2 Test de precision de detection...")
    # Scénarios : (is_attack, detected_as_attack)
    test_cases = [
        (True, True),   # TP
        (True, True),   # TP
        (True, True),   # TP
        (True, False),  # FN
        (False, False), # TN
        (False, False), # TN
        (False, False), # TN
        (False, True),  # FP
        (True, True),   # TP
        (True, True),   # TP
    ]
    
    for is_attack, detected in test_cases:
        metrics.record_detection(is_attack, detected)
    
    # Simulation de throughput
    print("\n 3  Test de débit reseau...")
    for i in range(20):
        bytes_transferred = np.random.randint(1000000, 5000000)
        duration = np.random.uniform(1, 3)
        metrics.measure_throughput(bytes_transferred, duration)
    
    # Simulation de latence
    print("\n 4 Test de latence...")
    for i in range(50):
        latency = np.random.normal(10, 3)  # Moyenne 10ms, écart-type 3ms
        metrics.measure_latency(max(1, latency))
    
    # Simulation d'overhead contrôleur
    print("\n 5 Test d'overhead du controleur...")
    for i in range(30):
        cpu = np.random.uniform(10, 40)
        memory = np.random.uniform(100, 300)
        metrics.measure_controller_overhead(cpu, memory)
        time.sleep(0.1)
    
    metrics.stop_measurement()
    
    # Génération des rapports
    print("\n Generation des rapports...")
    metrics.save_report()
    metrics.plot_metrics()
    metrics.print_summary()
    
    print("\n Tests de performance termines !")


if __name__ == '__main__':
    simulate_performance_test()

