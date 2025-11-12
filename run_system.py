#!/usr/bin/env python3
"""
H-SOAR HIDS Runner
Command-line interface for Host-based Security Orchestration and Automated Response
"""

import os
import sys
import json
import argparse
import logging
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from main import HSOARSystem

def setup_logging(level: str = 'INFO'):
    """Setup logging configuration"""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('logs/hids.log')
        ]
    )

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='H-SOAR: Host-based Security Orchestration and Automated Response',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start monitoring
  python run_system.py --mode monitor
  
  # Train ML model
  python run_system.py --mode train --dataset data/training_dataset.csv
  
  # Collect dataset
  python run_system.py --mode collect --duration 24 --label-mode auto
  
  # Test system
  python run_system.py --mode test
  
  # Check status
  python run_system.py --mode status
        """
    )
    
    parser.add_argument('--mode', 
                       choices=['monitor', 'train', 'collect', 'test', 'status'], 
                       default='monitor', 
                       help='Operation mode')
    
    parser.add_argument('--config', 
                       default='config/hids_config.json', 
                       help='Configuration file path')
    
    parser.add_argument('--dataset', 
                       help='Dataset path for training')
    
    parser.add_argument('--duration', 
                       type=int, 
                       default=24, 
                       help='Dataset collection duration in hours')
    
    parser.add_argument('--label-mode', 
                       choices=['manual', 'auto'], 
                       default='manual',
                       help='Dataset labeling mode')
    
    parser.add_argument('--log-level', 
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], 
                       default='INFO',
                       help='Logging level')
    
    parser.add_argument('--output', 
                       help='Output file for results')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_level)
    logger = logging.getLogger('HSOAR-Runner')
    
    try:
        # Create necessary directories
        os.makedirs('logs', exist_ok=True)
        os.makedirs('data', exist_ok=True)
        os.makedirs('models', exist_ok=True)
        
        # Initialize system
        logger.info("Initializing H-SOAR system...")
        system = HSOARSystem(args.config)
        
        # Execute based on mode
        if args.mode == 'monitor':
            print("=" * 80)
            print("H-SOAR: Host-based Security Orchestration and Automated Response")
            print("=" * 80)
            print("Starting Host-based Intrusion Detection System with FIM...")
            print("Monitoring file integrity and system events...")
            print("Press Ctrl+C to stop monitoring")
            print("=" * 80)
            
            system.start_monitoring()
        
        elif args.mode == 'train':
            print("=" * 80)
            print("H-SOAR TRAINING MODE")
            print("=" * 80)
            print("Training ML model for event classification...")
            
            if args.dataset:
                print(f"Using dataset: {args.dataset}")
            else:
                print("Using default dataset path")
            
            system.train_model(args.dataset)
            
            print("=" * 80)
            print("Training completed!")
            print("=" * 80)
        
        elif args.mode == 'collect':
            print("=" * 80)
            print("H-SOAR DATASET COLLECTION MODE")
            print("=" * 80)
            print(f"Collecting dataset for {args.duration} hours...")
            print(f"Labeling mode: {args.label_mode}")
            
            system.collect_dataset(args.duration, args.label_mode)
            
            print("=" * 80)
            print("Dataset collection completed!")
            print("=" * 80)
        
        elif args.mode == 'test':
            print("=" * 80)
            print("H-SOAR SYSTEM TEST MODE")
            print("=" * 80)
            print("Running comprehensive system test...")
            
            results = system.run_system_test()
            
            print("\n=== TEST RESULTS ===")
            for test_name, result in results.items():
                if test_name != 'overall_status':
                    status = "PASSED" if result else "FAILED"
                    print(f"{test_name}: {status}")
            
            print(f"\nOverall Status: {results.get('overall_status', 'UNKNOWN')}")
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"Results saved to: {args.output}")
            
            print("=" * 80)
        
        elif args.mode == 'status':
            print("=" * 80)
            print("H-SOAR SYSTEM STATUS")
            print("=" * 80)
            
            status = system.get_system_status()
            
            print(f"System Name: {status.get('system_name', 'Unknown')}")
            print(f"Version: {status.get('version', 'Unknown')}")
            print(f"Status: {status.get('status', 'Unknown')}")
            
            print("\n=== COMPONENT STATUS ===")
            components = status.get('components', {})
            for component_name, component_status in components.items():
                print(f"{component_name}: {component_status}")
            
            print("\n=== CONFIGURATION ===")
            config = status.get('config', {})
            for config_name, config_value in config.items():
                print(f"{config_name}: {config_value}")
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(status, f, indent=2)
                print(f"Status saved to: {args.output}")
            
            print("=" * 80)
    
    except KeyboardInterrupt:
        print("\nSystem stopped by user")
        logger.info("System stopped by user")
    except Exception as e:
        print(f"Error: {e}")
        logger.error(f"System error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()