#!/usr/bin/env python3
"""Export metrics to external monitoring systems"""
from app import create_app
from extensions import metrics
import json
import argparse

def export_metrics(output_format='json', file=None):
    """Export application metrics"""
    app = create_app()
    with app.app_context():
        # Collect metrics
        metric_data = metrics.export_metrics()
        
        # Format output
        if output_format == 'json':
            output = json.dumps(metric_data, indent=2)
        elif output_format == 'prometheus':
            output = metrics.export_prometheus_format()
        
        # Output to file or stdout
        if file:
            with open(file, 'w') as f:
                f.write(output)
        else:
            print(output)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Export application metrics')
    parser.add_argument('--format', choices=['json', 'prometheus'], default='json')
    parser.add_argument('--output', help='Output file path')
    args = parser.parse_args()
    
    export_metrics(args.format, args.output)
