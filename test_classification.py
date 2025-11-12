#!/usr/bin/env python3
"""Test ML classification with sample events"""

from main import HSOARSystem
import json

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
    
    print(f"Result:")
    print(json.dumps(result, indent=2))
    print("-"*80)
    print()

