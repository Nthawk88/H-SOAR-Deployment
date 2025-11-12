#!/usr/bin/env python3
"""
Convert HIDS2019 dataset to H-SOAR format
Converts HIDS2019 auditd logs to H-SOAR training dataset format
"""
import pandas as pd
import numpy as np
import os
import sys
from pathlib import Path
from datetime import datetime
import re

def calculate_criticality(filepath):
    """Calculate file path criticality score (1-10)"""
    if not filepath or pd.isna(filepath):
        return 3
    
    filepath = str(filepath).lower()
    
    # Critical system files
    if any(crit in filepath for crit in ['/etc/passwd', '/etc/shadow', '/etc/sudoers']):
        return 10
    elif '/etc/ssh/sshd_config' in filepath or '/root/.ssh' in filepath:
        return 9
    elif '/etc/' in filepath:
        return 7
    elif '/bin/' in filepath or '/sbin/' in filepath:
        return 8
    elif '/usr/bin/' in filepath or '/usr/sbin/' in filepath:
        return 6
    elif '/var/www/' in filepath:
        return 4
    elif '/tmp/' in filepath or '/var/tmp/' in filepath:
        return 1
    elif '/home/' in filepath:
        return 3
    elif '/var/log/' in filepath:
        return 5
    else:
        return 3

def is_suspicious_filepath(filepath):
    """Check if file path is suspicious"""
    if not filepath or pd.isna(filepath):
        return 0
    
    filepath = str(filepath).lower()
    suspicious_patterns = [
        'backdoor', 'shell', 'trojan', 'virus', 'malware',
        'exploit', 'payload', 'cmd', 'command', 'exec',
        '..', '...', '....'  # Path traversal
    ]
    
    return 1 if any(pattern in filepath for pattern in suspicious_patterns) else 0

def is_suspicious_extension(filepath):
    """Check if file extension is suspicious"""
    if not filepath or pd.isna(filepath):
        return 0
    
    filepath = str(filepath).lower()
    suspicious_extensions = ['.php', '.jsp', '.asp', '.aspx', '.sh', '.bat', 
                           '.cmd', '.ps1', '.exe', '.dll', '.py', '.pl', '.rb']
    
    return 1 if any(filepath.endswith(ext) for ext in suspicious_extensions) else 0

def is_suspicious_process(process):
    """Check if process is suspicious"""
    if not process or pd.isna(process):
        return 0
    
    process = str(process).lower()
    suspicious_processes = [
        'nc', 'netcat', 'ncat', 'wget', 'curl',
        'python', 'python3', 'perl', 'ruby',
        'bash', 'sh', 'zsh', 'nmap', 'masscan'
    ]
    
    return 1 if any(proc in process for proc in suspicious_processes) else 0

def is_shell_process(process):
    """Check if process is a shell"""
    if not process or pd.isna(process):
        return 0
    
    process = str(process).lower()
    shell_processes = ['bash', 'sh', 'zsh', 'csh', 'ksh', 'fish']
    
    return 1 if any(shell in process for shell in shell_processes) else 0

def is_web_server_process(process):
    """Check if process is a web server"""
    if not process or pd.isna(process):
        return 0
    
    process = str(process).lower()
    web_processes = ['nginx', 'apache2', 'httpd', 'lighttpd', 'php-fpm']
    
    return 1 if any(web in process for web in web_processes) else 0

def is_system_process(process):
    """Check if process is a system process"""
    if not process or pd.isna(process):
        return 0
    
    process = str(process).lower()
    system_processes = ['systemd', 'init', 'kthreadd', 'ksoftirqd', 'migration']
    
    return 1 if any(sys_proc in process for sys_proc in system_processes) else 0

def encode_event_type(event_type):
    """Encode event type as integer"""
    if pd.isna(event_type):
        return 0
    
    event_type = str(event_type).lower()
    mapping = {
        'file_integrity': 1,
        'process_execution': 2,
        'file_attribute': 3,
        'network': 4,
        'privilege': 5,
        'syscall': 2,  # Map syscall to process_execution
        'path': 1,     # Map path to file_integrity
    }
    
    for key, value in mapping.items():
        if key in event_type:
            return value
    
    return 0

def encode_action(action):
    """Encode action as integer"""
    if pd.isna(action):
        return 0
    
    action = str(action).lower()
    mapping = {
        'open': 1, 'read': 1,
        'write': 2, 'create': 2, 'modify': 2,
        'delete': 3, 'unlink': 3,
        'execute': 4, 'execve': 4,
        'chmod': 5,
        'chown': 6,
        'rename': 7,
        'truncate': 8,
        'bind': 9,
        'connect': 10,
        'setuid': 11,
        'setgid': 12,
    }
    
    for key, value in mapping.items():
        if key in action:
            return value
    
    return 0

def convert_hids2019(input_dir, output_file):
    """Convert HIDS2019 dataset to H-SOAR training format"""
    
    print("="*80)
    print("HIDS2019 to H-SOAR Dataset Converter")
    print("="*80)
    print(f"\nInput directory: {input_dir}")
    print(f"Output file: {output_file}\n")
    
    # Find CSV files
    input_path = Path(input_dir)
    csv_files = list(input_path.glob("*.csv"))
    
    if not csv_files:
        print(f"❌ Error: No CSV files found in {input_dir}")
        print(f"   Please check the directory path and ensure HIDS2019 dataset is extracted.")
        return False
    
    print(f"Found {len(csv_files)} CSV file(s)")
    
    # Load and combine CSV files
    all_dataframes = []
    
    for csv_file in csv_files:
        try:
            print(f"Loading {csv_file.name}...")
            df = pd.read_csv(csv_file, low_memory=False)
            print(f"  ✓ Loaded {len(df)} rows, {len(df.columns)} columns")
            
            # Show column names for debugging
            if len(all_dataframes) == 0:
                print(f"  Columns: {', '.join(df.columns[:10].tolist())}...")
            
            all_dataframes.append(df)
        except Exception as e:
            print(f"  ✗ Error loading {csv_file.name}: {e}")
            continue
    
    if not all_dataframes:
        print("❌ Error: No data loaded from CSV files")
        return False
    
    # Combine all dataframes
    print(f"\nCombining {len(all_dataframes)} dataset(s)...")
    combined_df = pd.concat(all_dataframes, ignore_index=True)
    print(f"✓ Total rows: {len(combined_df)}")
    
    # Detect column names (HIDS2019 may have different column names)
    print("\nDetecting column structure...")
    
    # Common column name variations
    filepath_col = None
    process_col = None
    user_col = None
    action_col = None
    event_type_col = None
    label_col = None
    timestamp_col = None
    
    for col in combined_df.columns:
        col_lower = col.lower()
        if not filepath_col and any(x in col_lower for x in ['file', 'path', 'name']):
            filepath_col = col
        if not process_col and any(x in col_lower for x in ['process', 'comm', 'exe', 'prog']):
            process_col = col
        if not user_col and any(x in col_lower for x in ['user', 'uid', 'auid', 'euid']):
            user_col = col
        if not action_col and any(x in col_lower for x in ['action', 'syscall', 'operation']):
            action_col = col
        if not event_type_col and any(x in col_lower for x in ['type', 'event']):
            event_type_col = col
        if not label_col and any(x in col_lower for x in ['label', 'class', 'category', 'malicious']):
            label_col = col
        if not timestamp_col and any(x in col_lower for x in ['time', 'date', 'timestamp']):
            timestamp_col = col
    
    print(f"  Filepath column: {filepath_col or 'NOT FOUND'}")
    print(f"  Process column: {process_col or 'NOT FOUND'}")
    print(f"  User column: {user_col or 'NOT FOUND'}")
    print(f"  Action column: {action_col or 'NOT FOUND'}")
    print(f"  Event type column: {event_type_col or 'NOT FOUND'}")
    print(f"  Label column: {label_col or 'NOT FOUND'}")
    
    # Extract features
    print("\nExtracting H-SOAR features...")
    
    hsoar_features = []
    
    for idx, row in combined_df.iterrows():
        if (idx + 1) % 1000 == 0:
            print(f"  Processing row {idx + 1}/{len(combined_df)}")
        
        features = {}
        
        # Get raw values
        filepath = row.get(filepath_col, '') if filepath_col else ''
        process = row.get(process_col, '') if process_col else ''
        user = row.get(user_col, '') if user_col else ''
        action = row.get(action_col, '') if action_col else ''
        event_type = row.get(event_type_col, '') if event_type_col else ''
        label = row.get(label_col, 'benign') if label_col else 'benign'
        
        # Event type and action
        features['event_type'] = encode_event_type(event_type) if event_type else 1
        features['action'] = encode_action(action) if action else 0
        
        # File path features
        features['filepath_criticality'] = calculate_criticality(filepath)
        features['filepath_depth'] = len(Path(str(filepath)).parts) if filepath else 0
        features['filepath_suspicious'] = is_suspicious_filepath(filepath)
        features['file_extension_suspicious'] = is_suspicious_extension(filepath)
        features['is_system_directory'] = 1 if filepath and any(d in str(filepath) for d in 
            ['/etc', '/bin', '/sbin', '/usr/bin', '/usr/sbin']) else 0
        features['is_web_directory'] = 1 if filepath and '/var/www' in str(filepath) else 0
        features['is_temp_directory'] = 1 if filepath and any(d in str(filepath) for d in 
            ['/tmp', '/var/tmp']) else 0
        
        # Process features
        features['process_suspicious'] = is_suspicious_process(process)
        features['process_is_shell'] = is_shell_process(process)
        features['process_is_web_server'] = is_web_server_process(process)
        features['process_is_system'] = is_system_process(process)
        features['process_name_length'] = len(str(process)) if process else 0
        
        # User features
        user_str = str(user)
        features['user_is_root'] = 1 if user_str in ['0', 'root'] or 'root' in user_str.lower() else 0
        features['user_is_system'] = 1 if user_str.isdigit() and int(user_str) < 1000 else 0
        features['user_is_web'] = 1 if any(u in user_str.lower() for u in 
            ['www-data', 'apache', 'nginx', 'httpd']) else 0
        
        # Action features
        action_str = str(action).lower()
        features['action_is_write'] = 1 if any(a in action_str for a in ['write', 'create', 'modify']) else 0
        features['action_is_delete'] = 1 if 'delete' in action_str or 'unlink' in action_str else 0
        features['action_is_execute'] = 1 if any(a in action_str for a in ['execute', 'execve', 'exec']) else 0
        features['action_is_attribute'] = 1 if any(a in action_str for a in ['chmod', 'chown']) else 0
        
        # Temporal features (extract from timestamp if available)
        if timestamp_col:
            try:
                ts = pd.to_datetime(row[timestamp_col])
                features['hour_of_day'] = ts.hour
                features['day_of_week'] = ts.dayofweek
            except:
                features['hour_of_day'] = 12
                features['day_of_week'] = 1
        else:
            features['hour_of_day'] = 12
            features['day_of_week'] = 1
        
        # Label (normalize to benign/suspicious/malicious)
        label_str = str(label).lower()
        if 'malicious' in label_str or 'attack' in label_str or 'malware' in label_str:
            features['label'] = 'malicious'
        elif 'suspicious' in label_str or 'anomaly' in label_str:
            features['label'] = 'suspicious'
        else:
            features['label'] = 'benign'
        
        hsoar_features.append(features)
    
    # Create H-SOAR format DataFrame
    print("\nCreating H-SOAR dataset...")
    hsoar_df = pd.DataFrame(hsoar_features)
    
    # Ensure correct column order
    feature_order = [
        'event_type', 'action',
        'filepath_criticality', 'filepath_depth', 'filepath_suspicious',
        'file_extension_suspicious', 'is_system_directory', 'is_web_directory', 'is_temp_directory',
        'process_suspicious', 'process_is_shell', 'process_is_web_server', 'process_is_system',
        'process_name_length',
        'user_is_root', 'user_is_system', 'user_is_web',
        'action_is_write', 'action_is_delete', 'action_is_execute', 'action_is_attribute',
        'hour_of_day', 'day_of_week',
        'label'
    ]
    
    # Reorder columns
    hsoar_df = hsoar_df[feature_order]
    
    # Save dataset
    os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
    hsoar_df.to_csv(output_file, index=False)
    
    # Print statistics
    print("\n" + "="*80)
    print("✅ Dataset conversion completed!")
    print("="*80)
    print(f"\nOutput file: {output_file}")
    print(f"Total samples: {len(hsoar_df)}")
    print(f"Features: {len(hsoar_df.columns) - 1}")
    print(f"File size: {os.path.getsize(output_file) / 1024 / 1024:.2f} MB")
    
    print(f"\nLabel distribution:")
    for label, count in hsoar_df['label'].value_counts().items():
        percentage = count / len(hsoar_df) * 100
        print(f"  {label:12s}: {count:6d} ({percentage:5.2f}%)")
    
    print("\n" + "="*80)
    print("Next steps:")
    print(f"1. Verify dataset: python verify_dataset.py")
    print(f"2. Train model: python run_system.py --mode train --dataset {output_file}")
    print("="*80)
    
    return True

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python convert_hids2019.py <input_dir> <output_file>")
        print("\nExample:")
        print("  python convert_hids2019.py data/external/HIDS2019-dataset/csv data/training_dataset.csv")
        print("\nOr use synthetic dataset:")
        print("  python generate_dataset.py --samples 10000 --output data/training_dataset.csv")
        sys.exit(1)
    
    input_dir = sys.argv[1]
    output_file = sys.argv[2]
    
    if not os.path.exists(input_dir):
        print(f"❌ Error: Input directory not found: {input_dir}")
        sys.exit(1)
    
    success = convert_hids2019(input_dir, output_file)
    sys.exit(0 if success else 1)

