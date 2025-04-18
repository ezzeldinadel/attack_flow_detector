import numpy as np
import pandas as pd
from datetime import datetime
from typing import List, Dict, Set, Optional
from dataclasses import dataclass
from collections import defaultdict
import networkx as nx
from sklearn.feature_extraction.text import TfidfVectorizer
from transformers import AutoTokenizer, AutoModel
import torch
from scipy.spatial.distance import cosine
import json

@dataclass
class Alert:
    id: str
    timestamp: datetime
    description: str
    source_ip: str
    destination_ip: str
    protocol: str
    port: int
    classification: str
    priority: int
    mitre_technique: Optional[str] = None
    embedding: Optional[np.ndarray] = None

class AlertProcessor:
    def __init__(self):
        self.tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")
        self.model = AutoModel.from_pretrained("bert-base-uncased")
        self.vectorizer = TfidfVectorizer(max_features=1000)
        self.alert_graph = nx.DiGraph()
        self.alert_sequences = []
        
    def parse_alert(self, alert_text: str) -> Alert:
        """Parse raw alert text into structured Alert object"""
        # Extract fields using regex patterns
        timestamp_str = re.search(r'(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)', alert_text).group(1)
        timestamp = datetime.strptime(timestamp_str, '%m/%d/%Y-%H:%M:%S.%f')
        
        # Extract IPs and ports
        ip_port_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)'
        source_match = re.search(f'{ip_port_pattern} ->', alert_text)
        dest_match = re.search(f'-> {ip_port_pattern}', alert_text)
        
        source_ip = source_match.group(1) if source_match else None
        source_port = int(source_match.group(2)) if source_match else None
        dest_ip = dest_match.group(1) if dest_match else None
        dest_port = int(dest_match.group(2)) if dest_match else None
        
        # Extract classification and priority
        classification = re.search(r'\[Classification: (.*?)\]', alert_text).group(1)
        priority = int(re.search(r'\[Priority: (\d+)\]', alert_text).group(1))
        
        return Alert(
            id=str(uuid.uuid4()),
            timestamp=timestamp,
            description=alert_text,
            source_ip=source_ip,
            destination_ip=dest_ip,
            protocol="TCP",  # Default, can be enhanced
            port=dest_port,
            classification=classification,
            priority=priority
        )
    
    def generate_embedding(self, alert: Alert) -> np.ndarray:
        """Generate BERT embedding for alert description"""
        inputs = self.tokenizer(alert.description, return_tensors="pt", truncation=True, max_length=512)
        with torch.no_grad():
            outputs = self.model(**inputs)
        return outputs.last_hidden_state.mean(dim=1).numpy()[0]
    
    def compute_similarity(self, alert1: Alert, alert2: Alert) -> float:
        """Compute cosine similarity between alert embeddings"""
        if alert1.embedding is None:
            alert1.embedding = self.generate_embedding(alert1)
        if alert2.embedding is None:
            alert2.embedding = self.generate_embedding(alert2)
        return 1 - cosine(alert1.embedding, alert2.embedding)
    
    def build_alert_graph(self, alerts: List[Alert], time_window: int = 3600):
        """Build temporal and semantic graph of alerts"""
        for alert in alerts:
            self.alert_graph.add_node(alert.id, alert=alert)
            
        # Add temporal edges
        for i, alert1 in enumerate(alerts):
            for alert2 in alerts[i+1:]:
                time_diff = (alert2.timestamp - alert1.timestamp).total_seconds()
                if 0 < time_diff <= time_window:
                    similarity = self.compute_similarity(alert1, alert2)
                    if similarity > 0.7:  # Threshold for semantic similarity
                        self.alert_graph.add_edge(
                            alert1.id, 
                            alert2.id,
                            weight=similarity,
                            time_diff=time_diff
                        )
    
    def detect_attack_sequences(self) -> List[List[Alert]]:
        """Detect potential attack sequences using graph analysis"""
        sequences = []
        visited = set()
        
        for node in self.alert_graph.nodes():
            if node not in visited:
                # Find all reachable nodes within time constraints
                reachable = nx.single_source_shortest_path_length(
                    self.alert_graph, 
                    node,
                    cutoff=3600  # 1 hour time window
                )
                
                # Extract sequence of alerts
                sequence = []
                for n, dist in sorted(reachable.items(), key=lambda x: x[1]):
                    if n not in visited:
                        sequence.append(self.alert_graph.nodes[n]['alert'])
                        visited.add(n)
                
                if len(sequence) > 1:  # Only consider sequences with multiple alerts
                    sequences.append(sequence)
        
        return sequences
    
    def correlate_alerts(self, alerts: List[str]) -> Dict:
        """Main correlation function"""
        # Parse alerts
        parsed_alerts = [self.parse_alert(alert) for alert in alerts]
        
        # Build alert graph
        self.build_alert_graph(parsed_alerts)
        
        # Detect sequences
        sequences = self.detect_attack_sequences()
        
        # Format output
        result = {
            "total_alerts": len(alerts),
            "detected_sequences": len(sequences),
            "sequences": [
                {
                    "sequence_id": str(uuid.uuid4()),
                    "alerts": [
                        {
                            "id": alert.id,
                            "timestamp": alert.timestamp.isoformat(),
                            "description": alert.description,
                            "source_ip": alert.source_ip,
                            "destination_ip": alert.destination_ip,
                            "classification": alert.classification,
                            "priority": alert.priority
                        }
                        for alert in sequence
                    ]
                }
                for sequence in sequences
            ]
        }
        
        return result 