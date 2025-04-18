import networkx as nx
import matplotlib.pyplot as plt
from typing import List, Dict
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
from datetime import datetime
import seaborn as sns
from alert_processor import Alert
from mitre_analyzer import MITREAnalyzer

class AttackVisualizer:
    def __init__(self):
        self.color_map = {
            "initial-access": "#FF9999",
            "execution": "#99FF99",
            "persistence": "#9999FF",
            "privilege-escalation": "#FFFF99",
            "defense-evasion": "#FF99FF",
            "credential-access": "#99FFFF",
            "discovery": "#FFCC99",
            "lateral-movement": "#CC99FF",
            "collection": "#99FFCC",
            "command-and-control": "#FFCCCC",
            "exfiltration": "#CCFF99",
            "impact": "#99CCFF"
        }
    
    def plot_attack_sequence(self, alerts: List[Alert], sequences: List[List[Alert]], 
                           mitre_analyzer: MITREAnalyzer):
        """Create interactive plot of attack sequence"""
        fig = make_subplots(rows=2, cols=1, 
                          subplot_titles=("Attack Timeline", "MITRE Tactics Coverage"),
                          vertical_spacing=0.2)
        
        # Plot timeline
        for i, sequence in enumerate(sequences):
            for alert in sequence:
                fig.add_trace(
                    go.Scatter(
                        x=[alert.timestamp],
                        y=[i],
                        mode='markers+text',
                        marker=dict(
                            size=10,
                            color=self.color_map.get(
                                mitre_analyzer.techniques[alert.mitre_technique].tactic,
                                "#CCCCCC"
                            )
                        ),
                        text=alert.description[:50] + "...",
                        textposition="top center",
                        name=f"Sequence {i+1}"
                    ),
                    row=1, col=1
                )
        
        # Plot tactics coverage
        tactics = set()
        for sequence in sequences:
            for alert in sequence:
                if alert.mitre_technique in mitre_analyzer.techniques:
                    tactics.add(mitre_analyzer.techniques[alert.mitre_technique].tactic)
        
        fig.add_trace(
            go.Bar(
                x=list(tactics),
                y=[1] * len(tactics),
                marker_color=[self.color_map.get(t, "#CCCCCC") for t in tactics],
                showlegend=False
            ),
            row=2, col=1
        )
        
        fig.update_layout(
            height=800,
            title_text="Attack Sequence Analysis",
            showlegend=True
        )
        
        return fig
    
    def plot_alert_network(self, alert_graph: nx.DiGraph, sequences: List[List[Alert]]):
        """Create network visualization of alert relationships"""
        plt.figure(figsize=(15, 10))
        
        # Create layout
        pos = nx.spring_layout(alert_graph, k=1, iterations=50)
        
        # Draw nodes
        nx.draw_networkx_nodes(
            alert_graph, pos,
            node_color='lightblue',
            node_size=500,
            alpha=0.6
        )
        
        # Draw edges
        nx.draw_networkx_edges(
            alert_graph, pos,
            edge_color='gray',
            arrows=True,
            arrowsize=20
        )
        
        # Add labels
        nx.draw_networkx_labels(
            alert_graph, pos,
            font_size=8,
            font_family='sans-serif'
        )
        
        plt.title("Alert Correlation Network")
        plt.axis('off')
        
        return plt.gcf()
    
    def create_attack_report(self, alerts: List[Alert], sequences: List[List[Alert]], 
                           mitre_analyzer: MITREAnalyzer) -> Dict:
        """Generate comprehensive attack report"""
        report = {
            "summary": {
                "total_alerts": len(alerts),
                "detected_sequences": len(sequences),
                "time_range": {
                    "start": min(a.timestamp for a in alerts).isoformat(),
                    "end": max(a.timestamp for a in alerts).isoformat()
                }
            },
            "sequences": []
        }
        
        for i, sequence in enumerate(sequences):
            sequence_analysis = mitre_analyzer.analyze_attack_sequence(
                [a.mitre_technique for a in sequence if a.mitre_technique]
            )
            
            report["sequences"].append({
                "sequence_id": i + 1,
                "alert_count": len(sequence),
                "tactics_covered": sequence_analysis["tactics_covered"],
                "patterns_detected": sequence_analysis["patterns"],
                "confidence_score": sequence_analysis["confidence_score"],
                "alerts": [
                    {
                        "id": alert.id,
                        "timestamp": alert.timestamp.isoformat(),
                        "description": alert.description,
                        "source_ip": alert.source_ip,
                        "destination_ip": alert.destination_ip,
                        "mitre_technique": alert.mitre_technique,
                        "classification": alert.classification,
                        "priority": alert.priority
                    }
                    for alert in sequence
                ]
            })
        
        return report
    
    def plot_alert_statistics(self, alerts: List[Alert]):
        """Create statistical visualizations of alerts"""
        # Convert to DataFrame for easier analysis
        df = pd.DataFrame([
            {
                "timestamp": a.timestamp,
                "source_ip": a.source_ip,
                "destination_ip": a.destination_ip,
                "classification": a.classification,
                "priority": a.priority
            }
            for a in alerts
        ])
        
        # Create subplots
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        
        # Plot 1: Alert frequency over time
        df['hour'] = df['timestamp'].dt.hour
        sns.histplot(data=df, x='hour', bins=24, ax=axes[0, 0])
        axes[0, 0].set_title('Alert Frequency by Hour')
        
        # Plot 2: Priority distribution
        sns.countplot(data=df, x='priority', ax=axes[0, 1])
        axes[0, 1].set_title('Alert Priority Distribution')
        
        # Plot 3: Top source IPs
        top_sources = df['source_ip'].value_counts().head(10)
        sns.barplot(x=top_sources.values, y=top_sources.index, ax=axes[1, 0])
        axes[1, 0].set_title('Top 10 Source IPs')
        
        # Plot 4: Classification distribution
        sns.countplot(data=df, y='classification', ax=axes[1, 1])
        axes[1, 1].set_title('Alert Classification Distribution')
        
        plt.tight_layout()
        return fig 