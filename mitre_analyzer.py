import json
from typing import Dict, List, Optional
from dataclasses import dataclass
import numpy as np
from transformers import AutoTokenizer, AutoModel
import torch
from scipy.spatial.distance import cosine

@dataclass
class MITRETechnique:
    id: str
    name: str
    description: str
    tactic: str
    subtechnique: bool
    parent_id: Optional[str] = None
    embedding: Optional[np.ndarray] = None

class MITREAnalyzer:
    def __init__(self, mitre_data_path: str = "mitre_attack.json"):
        self.techniques: Dict[str, MITRETechnique] = {}
        self.tactics: Dict[str, List[str]] = {}
        self.tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")
        self.model = AutoModel.from_pretrained("bert-base-uncased")
        self.load_mitre_data(mitre_data_path)
        
    def load_mitre_data(self, data_path: str):
        """Load MITRE ATT&CK data from JSON file"""
        with open(data_path, 'r') as f:
            data = json.load(f)
            
        for technique in data['techniques']:
            self.techniques[technique['id']] = MITRETechnique(
                id=technique['id'],
                name=technique['name'],
                description=technique['description'],
                tactic=technique['tactic'],
                subtechnique=technique.get('subtechnique', False),
                parent_id=technique.get('parent_id')
            )
            
        for tactic in data['tactics']:
            self.tactics[tactic['id']] = tactic['techniques']
    
    def generate_technique_embedding(self, technique: MITRETechnique) -> np.ndarray:
        """Generate BERT embedding for technique description"""
        text = f"{technique.name}. {technique.description}"
        inputs = self.tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
        with torch.no_grad():
            outputs = self.model(**inputs)
        return outputs.last_hidden_state.mean(dim=1).numpy()[0]
    
    def compute_similarity(self, text: str, technique: MITRETechnique) -> float:
        """Compute similarity between text and technique description"""
        if technique.embedding is None:
            technique.embedding = self.generate_technique_embedding(technique)
            
        # Generate embedding for input text
        inputs = self.tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
        with torch.no_grad():
            outputs = self.model(**inputs)
        text_embedding = outputs.last_hidden_state.mean(dim=1).numpy()[0]
        
        return 1 - cosine(text_embedding, technique.embedding)
    
    def map_alert_to_technique(self, alert_text: str, threshold: float = 0.7) -> Optional[str]:
        """Map alert text to most similar MITRE technique"""
        best_match = None
        best_score = threshold
        
        for technique in self.techniques.values():
            score = self.compute_similarity(alert_text, technique)
            if score > best_score:
                best_score = score
                best_match = technique.id
                
        return best_match
    
    def get_technique_sequence(self, technique_ids: List[str]) -> List[str]:
        """Get ordered sequence of techniques based on MITRE tactics"""
        tactic_order = {
            "initial-access": 1,
            "execution": 2,
            "persistence": 3,
            "privilege-escalation": 4,
            "defense-evasion": 5,
            "credential-access": 6,
            "discovery": 7,
            "lateral-movement": 8,
            "collection": 9,
            "command-and-control": 10,
            "exfiltration": 11,
            "impact": 12
        }
        
        # Get techniques with their tactics
        techniques_with_tactics = [
            (tech_id, self.techniques[tech_id].tactic)
            for tech_id in technique_ids
            if tech_id in self.techniques
        ]
        
        # Sort by tactic order and technique ID
        sorted_techniques = sorted(
            techniques_with_tactics,
            key=lambda x: (tactic_order.get(x[1], float('inf')), x[0])
        )
        
        return [tech_id for tech_id, _ in sorted_techniques]
    
    def analyze_attack_sequence(self, technique_ids: List[str]) -> Dict:
        """Analyze sequence of techniques to identify attack patterns"""
        sequence = self.get_technique_sequence(technique_ids)
        
        # Identify potential attack patterns
        patterns = []
        for i in range(len(sequence) - 1):
            current = self.techniques[sequence[i]]
            next_tech = self.techniques[sequence[i + 1]]
            
            # Check for common attack patterns
            if current.tactic == "initial-access" and next_tech.tactic == "execution":
                patterns.append("Initial Access -> Execution")
            elif current.tactic == "execution" and next_tech.tactic == "persistence":
                patterns.append("Execution -> Persistence")
            elif current.tactic == "privilege-escalation" and next_tech.tactic == "lateral-movement":
                patterns.append("Privilege Escalation -> Lateral Movement")
            
        return {
            "sequence": sequence,
            "patterns": patterns,
            "tactics_covered": list(set(tech.tactic for tech in self.techniques.values() 
                                      if tech.id in sequence)),
            "confidence_score": self.compute_sequence_confidence(sequence)
        }
    
    def compute_sequence_confidence(self, sequence: List[str]) -> float:
        """Compute confidence score for attack sequence"""
        if not sequence:
            return 0.0
            
        # Count consecutive techniques in same tactic
        same_tactic_count = 0
        for i in range(len(sequence) - 1):
            if self.techniques[sequence[i]].tactic == self.techniques[sequence[i + 1]].tactic:
                same_tactic_count += 1
                
        # Compute score based on sequence length and tactic consistency
        length_score = min(len(sequence) / 10, 1.0)  # Normalize by max expected length
        consistency_score = 1 - (same_tactic_count / max(len(sequence) - 1, 1))
        
        return 0.7 * length_score + 0.3 * consistency_score 