"""
Modul untuk monitoring jaringan dan analisis paket
untuk deteksi anomali berbasis ML
"""

import json
import time
import subprocess
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging

class NetworkMonitor:
    """Kelas untuk monitoring aktivitas jaringan"""
    
    def __init__(self, eve_log_path: str = "/var/log/suricata/eve.json"):
        self.eve_log_path = eve_log_path
        self.logger = self._setup_logger()
        self.foreign_ips = set()
        self.connection_patterns = {}
        
    def _setup_logger(self) -> logging.Logger:
        """Setup logger untuk network monitoring"""
        logger = logging.getLogger('NetworkMonitor')
        logger.setLevel(logging.INFO)
        
        handler = logging.FileHandler('logs/network_monitor.log')
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def parse_eve_log(self, lines: int = 100) -> List[Dict[str, Any]]:
        """Parse log Suricata eve.json untuk mendapatkan event terbaru"""
        events = []
        
        try:
            # Baca file eve.json dari akhir (event terbaru)
            with open(self.eve_log_path, 'r') as f:
                all_lines = f.readlines()
                
            # Ambil N baris terakhir
            recent_lines = all_lines[-lines:] if len(all_lines) > lines else all_lines
            
            for line in recent_lines:
                try:
                    event = json.loads(line.strip())
                    events.append(event)
                except json.JSONDecodeError:
                    continue
                    
        except FileNotFoundError:
            self.logger.warning(f"Eve log file not found: {self.eve_log_path}")
        except Exception as e:
            self.logger.error(f"Error parsing eve log: {e}")
            
        return events
    
    def extract_network_features(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Ekstrak fitur jaringan dari event Suricata"""
        features = {
            "total_events": len(events),
            "alert_events": 0,
            "flow_events": 0,
            "dns_events": 0,
            "http_events": 0,
            "unique_src_ips": set(),
            "unique_dst_ips": set(),
            "unique_ports": set(),
            "protocols": {},
            "packet_sizes": [],
            "connection_durations": [],
            "foreign_connections": 0,
            "suspicious_patterns": []
        }
        
        for event in events:
            event_type = event.get('event_type', '')
            
            # Hitung jenis event
            if event_type == 'alert':
                features["alert_events"] += 1
            elif event_type == 'flow':
                features["flow_events"] += 1
            elif event_type == 'dns':
                features["dns_events"] += 1
            elif event_type == 'http':
                features["http_events"] += 1
            
            # Ekstrak IP addresses
            if 'src_ip' in event:
                features["unique_src_ips"].add(event['src_ip'])
            if 'dest_ip' in event:
                features["unique_dst_ips"].add(event['dest_ip'])
                
            # Ekstrak port
            if 'src_port' in event:
                features["unique_ports"].add(event['src_port'])
            if 'dest_port' in event:
                features["unique_ports"].add(event['dest_port'])
            
            # Ekstrak protokol
            if 'proto' in event:
                proto = event['proto']
                features["protocols"][proto] = features["protocols"].get(proto, 0) + 1
            
            # Ekstrak ukuran paket
            if 'pktlen' in event:
                features["packet_sizes"].append(event['pktlen'])
            
            # Cek koneksi ke IP asing
            if self._is_foreign_ip(event.get('dest_ip', '')):
                features["foreign_connections"] += 1
                self.foreign_ips.add(event['dest_ip'])
            
            # Deteksi pola mencurigakan
            suspicious = self._detect_suspicious_patterns(event)
            if suspicious:
                features["suspicious_patterns"].extend(suspicious)
        
        # Konversi set ke list untuk JSON serialization
        features["unique_src_ips"] = list(features["unique_src_ips"])
        features["unique_dst_ips"] = list(features["unique_dst_ips"])
        features["unique_ports"] = list(features["unique_ports"])
        
        return features
    
    def _is_foreign_ip(self, ip: str) -> bool:
        """Cek apakah IP adalah IP asing (bukan private network)"""
        if not ip:
            return False
            
        # Private IP ranges
        private_ranges = [
            (r'^10\.', '10.0.0.0/8'),
            (r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', '172.16.0.0/12'),
            (r'^192\.168\.', '192.168.0.0/16'),
            (r'^127\.', '127.0.0.0/8'),
            (r'^169\.254\.', '169.254.0.0/16')
        ]
        
        for pattern, _ in private_ranges:
            if re.match(pattern, ip):
                return False
                
        return True
    
    def _detect_suspicious_patterns(self, event: Dict[str, Any]) -> List[str]:
        """Deteksi pola mencurigakan dalam event jaringan"""
        suspicious = []
        
        # Cek port scanning
        if event.get('event_type') == 'flow':
            if event.get('dest_port') and event.get('dest_port') > 1000:
                suspicious.append(f"High port number: {event['dest_port']}")
        
        # Cek protokol aneh
        if event.get('proto') == 'ICMP' and event.get('pktlen', 0) > 1000:
            suspicious.append("Large ICMP packet")
        
        # Cek DNS queries mencurigakan
        if event.get('event_type') == 'dns':
            query = event.get('dns', {}).get('rrname', '')
            if query and len(query) > 50:  # Domain name terlalu panjang
                suspicious.append(f"Suspicious DNS query: {query}")
        
        # Cek HTTP requests mencurigakan
        if event.get('event_type') == 'http':
            http_info = event.get('http', {})
            if http_info.get('hostname') and len(http_info['hostname']) > 100:
                suspicious.append(f"Suspicious HTTP hostname: {http_info['hostname']}")
        
        return suspicious
    
    def calculate_network_anomaly_score(self, features: Dict[str, Any]) -> float:
        """Hitung skor anomali berdasarkan fitur jaringan"""
        score = 0.0
        
        # Faktor 1: Rasio koneksi asing
        total_connections = features.get('total_events', 1)
        foreign_connections = features.get('foreign_connections', 0)
        if total_connections > 0:
            foreign_ratio = foreign_connections / total_connections
            score += foreign_ratio * 30  # Bobot 30%
        else:
            # Jika tidak ada koneksi, berikan skor 0
            score += 0
        
        # Faktor 2: Jumlah protokol unik
        unique_protocols = len(features.get('protocols', {}))
        if unique_protocols > 5:  # Normal: 2-3 protokol
            score += (unique_protocols - 5) * 5  # Bobot 5% per protokol ekstra
        
        # Faktor 3: Jumlah port unik
        unique_ports = len(features.get('unique_ports', []))
        if unique_ports > 10:  # Normal: 3-5 port
            score += (unique_ports - 10) * 2  # Bobot 2% per port ekstra
        
        # Faktor 4: Pola mencurigakan
        suspicious_count = len(features.get('suspicious_patterns', []))
        score += suspicious_count * 10  # Bobot 10% per pola mencurigakan
        
        # Faktor 5: Ukuran paket anomali
        packet_sizes = features.get('packet_sizes', [])
        if packet_sizes and len(packet_sizes) > 0:
            avg_packet_size = sum(packet_sizes) / len(packet_sizes)
            if avg_packet_size > 1500:  # MTU normal
                score += (avg_packet_size - 1500) / 100  # Bobot 1% per 100 byte
        
        # Normalisasi skor ke 0-100
        return min(score, 100.0)
    
    def get_network_metrics(self) -> Dict[str, Any]:
        """Dapatkan metrik jaringan lengkap"""
        events = self.parse_eve_log()
        features = self.extract_network_features(events)
        anomaly_score = self.calculate_network_anomaly_score(features)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "features": features,
            "anomaly_score": anomaly_score,
            "foreign_ips": list(self.foreign_ips)
        }
