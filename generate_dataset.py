#!/usr/bin/env python3
"""
H-SOAR HIDS Dataset Generator
Generates synthetic training dataset for ML model training
Based on IEEE paper specifications: 80% benign, 20% malicious events
"""

import os
import pandas as pd
import numpy as np
import random
from datetime import datetime, timedelta
from pathlib import Path
import argparse

class HIDSDatasetGenerator:
    """Generate synthetic HIDS training dataset"""
    
    def __init__(self, random_seed=42):
        """Initialize dataset generator"""
        np.random.seed(random_seed)
        random.seed(random_seed)
        
        # Feature order (must match ML classifier)
        self.feature_order = [
            'event_type', 'action',
            'filepath_criticality', 'filepath_depth', 'filepath_suspicious',
            'file_extension_suspicious', 'is_system_directory', 'is_web_directory', 'is_temp_directory',
            'process_suspicious', 'process_is_shell', 'process_is_web_server', 'process_is_system',
            'process_name_length',
            'user_is_root', 'user_is_system', 'user_is_web',
            'action_is_write', 'action_is_delete', 'action_is_execute', 'action_is_attribute',
            'hour_of_day', 'day_of_week',
            'label'  # Label is last column
        ]
        
        # File paths for benign events
        self.benign_filepaths = [
            '/tmp/temp_file.txt',
            '/tmp/log_file.log',
            '/var/log/syslog',
            '/var/log/auth.log',
            '/home/user/document.txt',
            '/home/user/file.pdf',
            '/var/www/html/index.html',
            '/var/www/html/style.css',
            '/usr/bin/nano',
            '/usr/bin/vim',
            '/etc/hosts',
            '/etc/resolv.conf',
            '/var/log/apache2/access.log',
            '/var/log/nginx/access.log',
            '/home/user/downloads/file.tar.gz',
            '/var/cache/apt/archives/package.deb',
        ]
        
        # File paths for malicious events
        self.malicious_filepaths = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/sudoers',
            '/root/.ssh/authorized_keys',
            '/var/www/html/backdoor.php',
            '/var/www/html/shell.php',
            '/var/www/html/cmd.php',
            '/tmp/exploit.sh',
            '/tmp/payload.py',
            '/bin/bash',
            '/usr/bin/python3',
            '/etc/ssh/sshd_config',
            '/var/www/html/webshell.jsp',
            '/var/www/html/trojan.php',
            '/tmp/malware.exe',
            '/root/.bashrc',
            '/etc/crontab',
            '/var/spool/cron/root',
        ]
        
        # Processes for benign events
        self.benign_processes = [
            'systemd', 'nginx', 'apache2', 'sshd',
            'nano', 'vim', 'gedit', 'code',
            'firefox', 'chrome', 'curl', 'wget',
            'apt', 'apt-get', 'dpkg', 'systemctl',
            'journalctl', 'logrotate', 'rsyslog',
        ]
        
        # Processes for malicious events
        self.malicious_processes = [
            'bash', 'sh', 'python3', 'python',
            'nc', 'netcat', 'ncat',
            'perl', 'ruby', 'php',
            'nmap', 'masscan',
            'wget', 'curl',
            'base64', 'xxd',
        ]
        
        # Users
        self.benign_users = ['www-data', 'admin', 'user', 'nginx', 'apache']
        self.malicious_users = ['root', '0']
        
        # Event types
        self.event_types = {
            'file_integrity': 1,
            'process_execution': 2,
            'file_attribute': 3,
            'network': 4,
            'privilege': 5,
        }
        
        # Actions
        self.actions = {
            'open': 1,
            'write': 2,
            'delete': 3,
            'execute': 4,
            'chmod': 5,
            'chown': 6,
        }
    
    def generate_benign_event(self) -> dict:
        """Generate a benign event"""
        filepath = random.choice(self.benign_filepaths)
        process = random.choice(self.benign_processes)
        user = random.choice(self.benign_users)
        action = random.choice(['open', 'write', 'execute'])
        event_type = random.choice(['file_integrity', 'process_execution'])
        
        # Calculate features
        features = self._calculate_features(
            filepath=filepath,
            process=process,
            user=user,
            action=action,
            event_type=event_type,
            is_malicious=False
        )
        
        features['label'] = 'benign'
        return features
    
    def generate_malicious_event(self) -> dict:
        """Generate a malicious event"""
        filepath = random.choice(self.malicious_filepaths)
        process = random.choice(self.malicious_processes)
        user = random.choice(self.malicious_users)
        action = random.choice(['write', 'execute', 'chmod', 'chown'])
        event_type = random.choice(['file_integrity', 'file_attribute', 'privilege'])
        
        # Calculate features
        features = self._calculate_features(
            filepath=filepath,
            process=process,
            user=user,
            action=action,
            event_type=event_type,
            is_malicious=True
        )
        
        features['label'] = 'malicious'
        return features
    
    def generate_suspicious_event(self) -> dict:
        """Generate a suspicious event (middle ground)"""
        # Mix of benign and malicious characteristics
        if random.random() < 0.5:
            filepath = random.choice(self.benign_filepaths)
            process = random.choice(self.malicious_processes)
        else:
            filepath = random.choice(self.malicious_filepaths)
            process = random.choice(self.benign_processes)
        
        user = random.choice(['root', 'admin', 'www-data'])
        action = random.choice(['write', 'execute', 'chmod'])
        event_type = random.choice(['file_integrity', 'process_execution'])
        
        features = self._calculate_features(
            filepath=filepath,
            process=process,
            user=user,
            action=action,
            event_type=event_type,
            is_malicious=False
        )
        
        features['label'] = 'suspicious'
        return features
    
    def _calculate_features(self, filepath: str, process: str, user: str, 
                          action: str, event_type: str, is_malicious: bool) -> dict:
        """Calculate all features for an event"""
        features = {}
        
        # Event type and action
        features['event_type'] = self.event_types.get(event_type, 0)
        features['action'] = self.actions.get(action, 0)
        
        # File path features
        features['filepath_criticality'] = self._calculate_criticality(filepath)
        features['filepath_depth'] = len(Path(filepath).parts)
        features['filepath_suspicious'] = 1 if any(p in filepath.lower() for p in 
            ['backdoor', 'shell', 'trojan', 'exploit', 'payload', 'malware', 'cmd']) else 0
        features['file_extension_suspicious'] = 1 if filepath.endswith(('.php', '.sh', '.py', '.jsp', '.exe')) else 0
        features['is_system_directory'] = 1 if any(filepath.startswith(d) for d in 
            ['/etc', '/bin', '/sbin', '/usr/bin', '/usr/sbin']) else 0
        features['is_web_directory'] = 1 if filepath.startswith('/var/www') else 0
        features['is_temp_directory'] = 1 if filepath.startswith('/tmp') or filepath.startswith('/var/tmp') else 0
        
        # Process features
        features['process_suspicious'] = 1 if any(p in process.lower() for p in 
            ['nc', 'netcat', 'ncat', 'bash', 'sh', 'python', 'perl', 'ruby', 'nmap']) else 0
        features['process_is_shell'] = 1 if any(s in process.lower() for s in ['bash', 'sh', 'zsh', 'csh']) else 0
        features['process_is_web_server'] = 1 if any(w in process.lower() for w in ['nginx', 'apache', 'httpd']) else 0
        features['process_is_system'] = 1 if any(s in process.lower() for s in ['systemd', 'init', 'kthread']) else 0
        features['process_name_length'] = len(process)
        
        # User features
        features['user_is_root'] = 1 if user == 'root' or user == '0' else 0
        features['user_is_system'] = 1 if user in ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'] else 0
        features['user_is_web'] = 1 if user in ['www-data', 'apache', 'nginx', 'httpd'] else 0
        
        # Action features
        features['action_is_write'] = 1 if action in ['write', 'create', 'modify'] else 0
        features['action_is_delete'] = 1 if action == 'delete' else 0
        features['action_is_execute'] = 1 if action == 'execute' else 0
        features['action_is_attribute'] = 1 if action in ['chmod', 'chown'] else 0
        
        # Temporal features (random for synthetic data)
        features['hour_of_day'] = random.randint(0, 23)
        features['day_of_week'] = random.randint(0, 6)
        
        # Add some noise for realism
        if not is_malicious:
            # Benign events might occasionally have high criticality (false positives)
            if random.random() < 0.1:
                features['filepath_criticality'] = random.randint(7, 9)
        else:
            # Malicious events should have high criticality
            if features['filepath_criticality'] < 7:
                features['filepath_criticality'] = random.randint(7, 10)
        
        return features
    
    def _calculate_criticality(self, filepath: str) -> int:
        """Calculate file path criticality score"""
        critical_files = {
            '/etc/passwd': 10,
            '/etc/shadow': 10,
            '/etc/sudoers': 10,
            '/etc/ssh/sshd_config': 9,
            '/root/.ssh/authorized_keys': 10,
            '/bin/bash': 9,
            '/usr/bin/python3': 8,
            '/etc/crontab': 9,
            '/var/spool/cron/root': 9,
        }
        
        if filepath in critical_files:
            return critical_files[filepath]
        
        if filepath.startswith('/etc/'):
            return random.randint(7, 9)
        elif filepath.startswith('/bin/') or filepath.startswith('/sbin/'):
            return random.randint(7, 9)
        elif filepath.startswith('/usr/bin/') or filepath.startswith('/usr/sbin/'):
            return random.randint(5, 7)
        elif filepath.startswith('/var/www/'):
            return random.randint(4, 6)
        elif filepath.startswith('/tmp/') or filepath.startswith('/var/tmp/'):
            return random.randint(1, 3)
        elif filepath.startswith('/home/'):
            return random.randint(3, 5)
        elif filepath.startswith('/var/log/'):
            return random.randint(4, 6)
        else:
            return random.randint(2, 5)
    
    def generate_dataset(self, n_samples: int = 10000, benign_ratio: float = 0.80, 
                        suspicious_ratio: float = 0.10, malicious_ratio: float = 0.10) -> pd.DataFrame:
        """Generate complete dataset"""
        print(f"Generating dataset with {n_samples} samples...")
        print(f"Distribution: {benign_ratio*100:.1f}% benign, {suspicious_ratio*100:.1f}% suspicious, {malicious_ratio*100:.1f}% malicious")
        
        events = []
        
        n_benign = int(n_samples * benign_ratio)
        n_suspicious = int(n_samples * suspicious_ratio)
        n_malicious = n_samples - n_benign - n_suspicious
        
        # Generate benign events
        print(f"Generating {n_benign} benign events...")
        for i in range(n_benign):
            if (i + 1) % 1000 == 0:
                print(f"  Generated {i + 1}/{n_benign} benign events")
            events.append(self.generate_benign_event())
        
        # Generate suspicious events
        print(f"Generating {n_suspicious} suspicious events...")
        for i in range(n_suspicious):
            if (i + 1) % 100 == 0:
                print(f"  Generated {i + 1}/{n_suspicious} suspicious events")
            events.append(self.generate_suspicious_event())
        
        # Generate malicious events
        print(f"Generating {n_malicious} malicious events...")
        for i in range(n_malicious):
            if (i + 1) % 100 == 0:
                print(f"  Generated {i + 1}/{n_malicious} malicious events")
            events.append(self.generate_malicious_event())
        
        # Create DataFrame
        df = pd.DataFrame(events)
        
        # Ensure all features are present
        for feature in self.feature_order:
            if feature not in df.columns:
                df[feature] = 0
        
        # Reorder columns
        df = df[self.feature_order]
        
        # Shuffle dataset
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        print(f"\nDataset generated successfully!")
        print(f"Total samples: {len(df)}")
        print(f"Features: {len(df.columns) - 1}")  # Exclude label
        print(f"\nLabel distribution:")
        print(df['label'].value_counts())
        print(f"\nLabel percentages:")
        print(df['label'].value_counts(normalize=True) * 100)
        
        return df

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Generate H-SOAR HIDS training dataset')
    parser.add_argument('--samples', type=int, default=10000, help='Number of samples to generate')
    parser.add_argument('--benign-ratio', type=float, default=0.80, help='Ratio of benign events')
    parser.add_argument('--suspicious-ratio', type=float, default=0.10, help='Ratio of suspicious events')
    parser.add_argument('--malicious-ratio', type=float, default=0.10, help='Ratio of malicious events')
    parser.add_argument('--output', type=str, default='data/training_dataset.csv', help='Output CSV file path')
    parser.add_argument('--seed', type=int, default=42, help='Random seed')
    
    args = parser.parse_args()
    
    # Validate ratios
    total_ratio = args.benign_ratio + args.suspicious_ratio + args.malicious_ratio
    if abs(total_ratio - 1.0) > 0.01:
        print(f"Error: Ratios must sum to 1.0 (got {total_ratio})")
        return
    
    # Create output directory
    os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else '.', exist_ok=True)
    
    # Generate dataset
    generator = HIDSDatasetGenerator(random_seed=args.seed)
    df = generator.generate_dataset(
        n_samples=args.samples,
        benign_ratio=args.benign_ratio,
        suspicious_ratio=args.suspicious_ratio,
        malicious_ratio=args.malicious_ratio
    )
    
    # Save dataset
    df.to_csv(args.output, index=False)
    print(f"\nDataset saved to: {args.output}")
    print(f"File size: {os.path.getsize(args.output) / 1024 / 1024:.2f} MB")
    
    # Print statistics
    print("\n" + "="*80)
    print("DATASET STATISTICS")
    print("="*80)
    print(f"\nTotal samples: {len(df)}")
    print(f"Features: {len(df.columns) - 1}")
    print(f"\nLabel distribution:")
    for label, count in df['label'].value_counts().items():
        percentage = count / len(df) * 100
        print(f"  {label:12s}: {count:6d} ({percentage:5.2f}%)")
    
    print(f"\nFeature statistics:")
    numeric_features = df.select_dtypes(include=[np.number]).columns
    for feature in numeric_features:
        if feature != 'label':
            print(f"  {feature:30s}: mean={df[feature].mean():6.2f}, std={df[feature].std():6.2f}, min={df[feature].min():4.0f}, max={df[feature].max():4.0f}")
    
    print("\n" + "="*80)
    print("Dataset generation completed!")
    print("="*80)
    print(f"\nNext steps:")
    print(f"1. Review dataset: {args.output}")
    print(f"2. Train ML model: python run_system.py --mode train --dataset {args.output}")
    print(f"3. Test system: python run_system.py --mode test")

if __name__ == "__main__":
    main()


