#!/usr/bin/env python3
"""Debug ML model to check label encoding and predictions"""

from main import HSOARSystem
import joblib
import numpy as np

# Initialize system
system = HSOARSystem()

# Check label encoder
print("="*80)
print("Label Encoder Check")
print("="*80)
print(f"Label encoder classes: {system.ml_classifier.label_encoder.classes_}")
print(f"Label encoder mapping:")
for i, label in enumerate(system.ml_classifier.label_encoder.classes_):
    print(f"  {i} = {label}")

# Check if model is trained
print(f"\nModel trained: {system.ml_classifier.is_trained}")
print(f"Models available: {list(system.ml_classifier.models.keys())}")

# Load model file directly to check
print("\n" + "="*80)
print("Model File Check")
print("="*80)
try:
    model_data = joblib.load('models/hids_classifier.pkl')
    print(f"Model file keys: {list(model_data.keys())}")
    if 'label_encoder' in model_data:
        le = model_data['label_encoder']
        print(f"Label encoder in file - classes: {le.classes_}")
        for i, label in enumerate(le.classes_):
            print(f"  {i} = {label}")
except Exception as e:
    print(f"Error loading model: {e}")

# Test with known benign event
print("\n" + "="*80)
print("Test Classification")
print("="*80)

test_event = {
    'event_type': 'file_integrity',
    'action': 'read',
    'filepath': '/home/user/document.txt',
    'process': 'cat',
    'user': 'user'
}

features = system.feature_extractor.extract_features(test_event)
print(f"\nExtracted features:")
for key, value in features.items():
    print(f"  {key}: {value}")

result = system.ml_classifier.classify(features)
print(f"\nClassification result:")
print(f"  Classification: {result.get('classification')}")
print(f"  Confidence: {result.get('confidence')}")
print(f"  Ensemble prediction (encoded): {result.get('ensemble_prediction')}")
print(f"  Individual predictions: {result.get('individual_predictions')}")

# Check what the encoded prediction means
if 'ensemble_prediction' in result:
    pred_encoded = result['ensemble_prediction']
    try:
        decoded = system.ml_classifier.label_encoder.inverse_transform([pred_encoded])[0]
        print(f"  Decoded prediction: {decoded}")
    except Exception as e:
        print(f"  Error decoding: {e}")

