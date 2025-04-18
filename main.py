import argparse
import json
from typing import List
from alert_processor import AlertProcessor
from mitre_analyzer import MITREAnalyzer
from visualizer import AttackVisualizer
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def load_alerts(file_path: str) -> List[str]:
    """Load alerts from file"""
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def save_report(report: dict, output_dir: str):
    """Save analysis report and visualizations"""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Save JSON report
    with open(output_path / "attack_report.json", 'w') as f:
        json.dump(report, f, indent=2)
    
    logger.info(f"Report saved to {output_path / 'attack_report.json'}")

def main():
    parser = argparse.ArgumentParser(description="Attack Flow Detector")
    parser.add_argument("--alerts", required=True, help="Path to alerts file")
    parser.add_argument("--mitre-data", required=True, help="Path to MITRE ATT&CK data file")
    parser.add_argument("--output-dir", default="output", help="Output directory for reports")
    parser.add_argument("--time-window", type=int, default=3600, 
                       help="Time window for alert correlation in seconds")
    parser.add_argument("--similarity-threshold", type=float, default=0.7,
                       help="Similarity threshold for alert correlation")
    
    args = parser.parse_args()
    
    try:
        # Initialize components
        logger.info("Initializing components...")
        alert_processor = AlertProcessor()
        mitre_analyzer = MITREAnalyzer(args.mitre_data)
        visualizer = AttackVisualizer()
        
        # Load and process alerts
        logger.info("Loading alerts...")
        alerts = load_alerts(args.alerts)
        
        logger.info("Processing alerts...")
        correlation_result = alert_processor.correlate_alerts(alerts)
        
        # Map alerts to MITRE techniques
        logger.info("Mapping alerts to MITRE techniques...")
        for sequence in correlation_result["sequences"]:
            for alert in sequence["alerts"]:
                alert["mitre_technique"] = mitre_analyzer.map_alert_to_technique(
                    alert["description"],
                    args.similarity_threshold
                )
        
        # Generate visualizations
        logger.info("Generating visualizations...")
        sequence_plot = visualizer.plot_attack_sequence(
            correlation_result["sequences"],
            mitre_analyzer
        )
        network_plot = visualizer.plot_alert_network(
            alert_processor.alert_graph,
            correlation_result["sequences"]
        )
        stats_plot = visualizer.plot_alert_statistics(alerts)
        
        # Create comprehensive report
        logger.info("Generating report...")
        report = visualizer.create_attack_report(
            alerts,
            correlation_result["sequences"],
            mitre_analyzer
        )
        
        # Save results
        logger.info("Saving results...")
        save_report(report, args.output_dir)
        
        logger.info("Analysis complete!")
        
    except Exception as e:
        logger.error(f"Error during analysis: {str(e)}")
        raise

if __name__ == "__main__":
    main() 