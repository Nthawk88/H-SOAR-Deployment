#!/usr/bin/env python3
"""
Convert paper datasets (LID-DS 2021, ADFA-LD) to H-SOAR format
Datasets from published research papers
"""
import pandas as pd
import numpy as np
import os
import sys
from pathlib import Path
from datetime import datetime
import re
import json

def calculate_criticality(filepath):
    """Calculate file path criticality score (1-10)"""
    if not filepath or pd.isna(filepath):
        return 3
    
    filepath = str(filepath).lower()
    
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
        '..', '...', '....'
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

def parse_lid_ds_2021(input_dir):
    """Parse LID-DS 2021 dataset (Linux Intrusion Detection Dataset)"""
    print("="*80)
    print("Parsing LID-DS 2021 Dataset")
    print("Paper: Martinez-Torres et al., Future Generation Computer Systems 2022")
    print("="*80)
    print(f"\nInput directory: {input_dir}\n")
    
    events = []
    input_path = Path(input_dir)
    
    # LID-DS structure: scenarios with auditd logs
    # Look for scenario directories
    scenario_dirs = [d for d in input_path.iterdir() if d.is_dir() and not d.name.startswith('.')]
    
    if not scenario_dirs:
        # Try nested structure
        for subdir in input_path.iterdir():
            if subdir.is_dir():
                scenario_dirs.extend([d for d in subdir.iterdir() if d.is_dir()])
    
    print(f"Found {len(scenario_dirs)} scenario(s)")
    
    for scenario_dir in scenario_dirs:
        scenario_name = scenario_dir.name
        print(f"\nProcessing scenario: {scenario_name}")
        
        # Determine label based on scenario name
        is_attack = any(keyword in scenario_name.lower() for keyword in 
            ['attack', 'exploit', 'malware', 'intrusion', 'backdoor', 'shell'])
        
        # Look for auditd logs
        audit_files = []
        for pattern in ['*.log', 'audit*', '*.audit', '**/audit.log', '**/*audit*']:
            audit_files.extend(list(scenario_dir.rglob(pattern)))
        
        if not audit_files:
            print(f"  No audit logs found, skipping...")
            continue
        
        print(f"  Found {len(audit_files)} audit log file(s)")
        
        for log_file in audit_files[:10]:  # Limit to first 10 files per scenario
            try:
                print(f"    Parsing {log_file.name}...")
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    line_count = 0
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        
                        # Parse auditd log line
                        # Format: type=PATH msg=audit(...): item=0 name="..." ...
                        if 'type=PATH' in line or 'type=SYSCALL' in line:
                            # Extract file path
                            name_match = re.search(r'name="([^"]+)"', line)
                            filepath = name_match.group(1) if name_match else ''
                            
                            # Extract process
                            comm_match = re.search(r'comm="([^"]+)"', line)
                            exe_match = re.search(r'exe="([^"]+)"', line)
                            process = comm_match.group(1) if comm_match else (exe_match.group(1) if exe_match else '')
                            
                            # Extract user
                            uid_match = re.search(r'uid=(\d+)', line)
                            auid_match = re.search(r'auid=(\d+)', line)
                            user = uid_match.group(1) if uid_match else (auid_match.group(1) if auid_match else '0')
                            
                            # Extract action type
                            action = 'write'
                            if 'type=SYSCALL' in line:
                                action = 'execute'
                            elif 'nametype=DELETE' in line:
                                action = 'delete'
                            elif 'nametype=CREATE' in line:
                                action = 'create'
                            
                            # Determine event type
                            event_type = 'file_integrity'
                            if 'type=SYSCALL' in line and 'execve' in line:
                                event_type = 'process_execution'
                            
                            label = 'malicious' if is_attack else 'benign'
                            
                            event = {
                                'event_type': event_type,
                                'action': action,
                                'filepath': filepath,
                                'process': process,
                                'user': user,
                                'label': label
                            }
                            events.append(event)
                            line_count += 1
                            
                            if line_count >= 1000:  # Limit per file
                                break
                                
            except Exception as e:
                print(f"    Warning: Could not parse {log_file}: {e}")
                continue
    
    print(f"\n✅ Extracted {len(events)} events from LID-DS 2021")
    return events

def parse_adfa_ld(input_dir):
    """Parse ADFA-LD dataset (UNSW Canberra)"""
    print("="*80)
    print("Parsing ADFA-LD Dataset")
    print("Paper: Creech & Hu, IEEE TIFS 2014")
    print("="*80)
    print(f"\nInput directory: {input_dir}\n")
    
    events = []
    input_path = Path(input_dir)
    
    # ADFA-LD structure: Training_Data_Master, Attack_Data_Master, Validation_Data_Master
    dataset_types = {
        'Training_Data_Master': 'benign',
        'Validation_Data_Master': 'benign',
        'Attack_Data_Master': 'malicious'
    }
    
    for dataset_type, label in dataset_types.items():
        dataset_path = input_path / dataset_type
        
        if not dataset_path.exists():
            print(f"  {dataset_type} not found, skipping...")
            continue
        
        print(f"Processing {dataset_type} ({label})...")
        
        # ADFA-LD contains system call traces (one syscall per line)
        trace_files = list(dataset_path.glob("*"))
        trace_files = [f for f in trace_files if f.is_file()]
        
        print(f"  Found {len(trace_files)} trace file(s)")
        
        for trace_file in trace_files[:50]:  # Limit to first 50 files
            try:
                with open(trace_file, 'r', encoding='utf-8', errors='ignore') as f:
                    syscalls = []
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        
                        # ADFA-LD format: system call numbers
                        try:
                            syscall_num = int(line.split()[0])
                            syscalls.append(syscall_num)
                        except:
                            continue
                    
                    # Create events from syscall sequence
                    # Map common syscalls to file operations
                    for syscall in syscalls[:100]:  # Limit per trace
                        # Common syscalls: 2=open, 3=read, 4=write, 5=openat, 59=execve
                        if syscall in [59, 11]:  # execve, execveat
                            event = {
                                'event_type': 'process_execution',
                                'action': 'execute',
                                'filepath': '/bin/sh',  # Placeholder
                                'process': 'unknown',
                                'user': '0',
                                'label': label
                            }
                        elif syscall in [2, 5, 257]:  # open, openat, openat2
                            event = {
                                'event_type': 'file_integrity',
                                'action': 'open',
                                'filepath': '/etc/passwd',  # Placeholder
                                'process': 'unknown',
                                'user': '0',
                                'label': label
                            }
                        elif syscall in [4, 278]:  # write, pwritev2
                            event = {
                                'event_type': 'file_integrity',
                                'action': 'write',
                                'filepath': '/etc/passwd',  # Placeholder
                                'process': 'unknown',
                                'user': '0',
                                'label': label
                            }
                        else:
                            continue
                        
                        events.append(event)
                        
            except Exception as e:
                print(f"    Warning: Could not parse {trace_file}: {e}")
                continue
    
    print(f"\n✅ Extracted {len(events)} events from ADFA-LD")
    return events

def convert_to_hsoar_format(events, output_file):
    """Convert events to H-SOAR format"""
    print(f"\n{'='*80}")
    print("Converting to H-SOAR Format")
    print(f"{'='*80}\n")
    print(f"Processing {len(events)} events...")
    
    hsoar_features = []
    
    for idx, event in enumerate(events):
        if (idx + 1) % 1000 == 0:
            print(f"  Processing {idx + 1}/{len(events)} events...")
        
        filepath = str(event.get('filepath', ''))
        process = str(event.get('process', ''))
        user = str(event.get('user', '0'))
        action = str(event.get('action', ''))
        event_type = str(event.get('event_type', ''))
        label = str(event.get('label', 'benign')).lower()
        
        features = {}
        
        # Event type and action
        event_type_map = {
            'file_integrity': 1, 'file': 1, 'path': 1,
            'process_execution': 2, 'process': 2, 'syscall': 2, 'execve': 2,
            'file_attribute': 3, 'attribute': 3,
            'network': 4,
            'privilege': 5
        }
        features['event_type'] = next((v for k, v in event_type_map.items() if k in event_type.lower()), 1)
        
        action_map = {
            'open': 1, 'read': 1,
            'write': 2, 'create': 2, 'modify': 2,
            'delete': 3, 'unlink': 3,
            'execute': 4, 'execve': 4, 'exec': 4,
            'chmod': 5,
            'chown': 6
        }
        features['action'] = next((v for k, v in action_map.items() if k in action.lower()), 2)
        
        # File path features
        features['filepath_criticality'] = calculate_criticality(filepath)
        features['filepath_depth'] = len(Path(filepath).parts) if filepath and filepath != '/' else 0
        features['filepath_suspicious'] = is_suspicious_filepath(filepath)
        features['file_extension_suspicious'] = is_suspicious_extension(filepath)
        features['is_system_directory'] = 1 if filepath and any(d in filepath for d in 
            ['/etc', '/bin', '/sbin', '/usr/bin', '/usr/sbin']) else 0
        features['is_web_directory'] = 1 if filepath and '/var/www' in filepath else 0
        features['is_temp_directory'] = 1 if filepath and any(d in filepath for d in 
            ['/tmp', '/var/tmp']) else 0
        
        # Process features
        features['process_suspicious'] = is_suspicious_process(process)
        features['process_is_shell'] = is_shell_process(process)
        features['process_is_web_server'] = is_web_server_process(process)
        features['process_is_system'] = is_system_process(process)
        features['process_name_length'] = len(process) if process and process != 'unknown' else 0
        
        # User features
        features['user_is_root'] = 1 if user in ['0', 'root'] or 'root' in user.lower() else 0
        features['user_is_system'] = 1 if user.isdigit() and int(user) < 1000 else 0
        features['user_is_web'] = 1 if any(u in user.lower() for u in 
            ['www-data', 'apache', 'nginx', 'httpd']) else 0
        
        # Action features
        action_str = action.lower()
        features['action_is_write'] = 1 if any(a in action_str for a in ['write', 'create', 'modify']) else 0
        features['action_is_delete'] = 1 if 'delete' in action_str or 'unlink' in action_str else 0
        features['action_is_execute'] = 1 if any(a in action_str for a in ['execute', 'execve', 'exec']) else 0
        features['action_is_attribute'] = 1 if any(a in action_str for a in ['chmod', 'chown']) else 0
        
        # Temporal features
        features['hour_of_day'] = 12  # Placeholder
        features['day_of_week'] = 1   # Placeholder
        
        # Label
        if 'malicious' in label or 'attack' in label or 'malware' in label:
            features['label'] = 'malicious'
        elif 'suspicious' in label or 'anomaly' in label:
            features['label'] = 'suspicious'
        else:
            features['label'] = 'benign'
        
        hsoar_features.append(features)
    
    # Create DataFrame
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
    
    # Add missing columns
    for col in feature_order:
        if col not in hsoar_df.columns:
            hsoar_df[col] = 0
    
    hsoar_df = hsoar_df[feature_order]
    
    # Shuffle
    hsoar_df = hsoar_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Save
    os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
    hsoar_df.to_csv(output_file, index=False)
    
    # Print statistics
    print(f"\n{'='*80}")
    print("✅ Dataset conversion completed!")
    print(f"{'='*80}")
    print(f"\nOutput file: {output_file}")
    print(f"Total samples: {len(hsoar_df)}")
    print(f"Features: {len(hsoar_df.columns) - 1}")
    print(f"File size: {os.path.getsize(output_file) / 1024 / 1024:.2f} MB")
    
    print(f"\nLabel distribution:")
    for label, count in hsoar_df['label'].value_counts().items():
        percentage = count / len(hsoar_df) * 100
        print(f"  {label:12s}: {count:6d} ({percentage:5.2f}%)")
    
    print(f"\n{'='*80}")
    print("Next steps:")
    print(f"1. Verify dataset: python verify_dataset.py")
    print(f"2. Train model: python run_system.py --mode train --dataset {output_file}")
    print(f"{'='*80}")
    
    return True

def main():
    if len(sys.argv) < 3:
        print("Usage: python convert_paper_dataset.py <input_dir> <output_file>")
        print("\nExamples:")
        print("  python convert_paper_dataset.py data/external/lid_ds data/training_dataset.csv")
        print("  python convert_paper_dataset.py data/external/ADFA-LD data/training_dataset.csv")
        print("\nSupported datasets:")
        print("  - LID-DS 2021 (Linux Intrusion Detection Dataset)")
        print("    Paper: Martinez-Torres et al., Future Generation Computer Systems 2022")
        print("    Download: https://zenodo.org/record/5773804")
        print("")
        print("  - ADFA-LD (UNSW Canberra)")
        print("    Paper: Creech & Hu, IEEE TIFS 2014")
        print("    Download: https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-LD")
        sys.exit(1)
    
    input_dir = sys.argv[1]
    output_file = sys.argv[2]
    
    if not os.path.exists(input_dir):
        print(f"❌ Error: Input directory not found: {input_dir}")
        sys.exit(1)
    
    # Detect dataset type and parse
    events = []
    
    input_path = Path(input_dir)
    input_lower = str(input_dir).lower()
    
    if 'lid' in input_lower or 'lid_ds' in input_lower:
        events = parse_lid_ds_2021(input_dir)
    elif 'adfa' in input_lower:
        events = parse_adfa_ld(input_dir)
    else:
        # Try to auto-detect
        if (input_path / 'Training_Data_Master').exists() or (input_path / 'Attack_Data_Master').exists():
            events = parse_adfa_ld(input_dir)
        else:
            # Assume LID-DS format
            events = parse_lid_ds_2021(input_dir)
    
    if not events:
        print("❌ Error: No events extracted from dataset")
        print("\nPlease ensure:")
        print("  1. Dataset is in supported format (LID-DS 2021 or ADFA-LD)")
        print("  2. Dataset files are accessible")
        print("  3. Dataset structure matches expected format")
        sys.exit(1)
    
    # Convert to H-SOAR format
    success = convert_to_hsoar_format(events, output_file)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()

