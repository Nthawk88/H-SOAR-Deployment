#!/usr/bin/env python3
"""Test ML classification with sample events"""

from main import HSOARSystem
import json
import numpy as np

# Initialize system (no need to call initialize())
system = HSOARSystem()

# Test classification with different events
test_events = [
    {
        'name': 'Suspicious write to /etc/passwd',
        'event': {
            'event_type': 'file_integrity',
            'action': 'write',
            'filepath': '/etc/passwd',
            'process': 'bash',
            'user': 'root'
        }
    },
    {
        'name': 'Normal file read',
        'event': {
            'event_type': 'file_integrity',
            'action': 'read',
            'filepath': '/home/user/document.txt',
            'process': 'cat',
            'user': 'user'
        }
    },
    {
        'name': 'Malicious process execution',
        'event': {
            'event_type': 'process_execution',
            'action': 'execute',
            'filepath': '/tmp/suspicious_script.sh',
            'process': 'bash',
            'user': 'root'
        }
    }
]

print("="*80)
print("H-SOAR ML Classification Test")
print("="*80)
print()

for test in test_events:
    print(f"Test: {test['name']}")
    print(f"Event: {json.dumps(test['event'], indent=2)}")
    
    # Extract features first
    features = system.feature_extractor.extract_features(test['event'])
    
    # Classify
    result = system.ml_classifier.classify(features)
    
    # Convert numpy types to Python native types for JSON serialization
    def convert_to_native(obj):
        if isinstance(obj, dict):
            return {k: convert_to_native(v) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [convert_to_native(item) for item in obj]
        elif isinstance(obj, (np.integer, np.int64, np.int32)):
            return int(obj)
        elif isinstance(obj, (np.floating, np.float64, np.float32)):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        else:
            return obj
    
    result_serializable = convert_to_native(result)
    
    print(f"Result:")
    print(json.dumps(result_serializable, indent=2))
    print("-"*80)
    print()

