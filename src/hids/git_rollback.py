#!/usr/bin/env python3
"""
Git Rollback System for H-SOAR HIDS
Automated rollback system using Git for file recovery
"""

import os
import json
import logging
import subprocess
import shutil
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

class GitRollbackSystem:
    """
    Git-based rollback system for automated file recovery
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize Git rollback system"""
        self.config = config
        self.logger = logging.getLogger('GitRollback')
        
        # Configuration
        self.enabled = config.get('enabled', True)
        self.git_repos = config.get('git_repos', {})
        self.auto_rollback = config.get('auto_rollback', True)
        self.rollback_threshold = config.get('rollback_threshold', 0.8)
        
        # Rollback history
        self.rollback_history = []
        
        # Initialize Git repositories
        self._initialize_git_repos()
    
    def _initialize_git_repos(self):
        """Initialize Git repositories for monitored directories"""
        if not self.enabled:
            return
        
        for directory, repo_url in self.git_repos.items():
            try:
                if os.path.exists(directory):
                    # Check if directory is already a Git repository
                    git_dir = os.path.join(directory, '.git')
                    if not os.path.exists(git_dir):
                        self.logger.info(f"Initializing Git repository in {directory}")
                        
                        # Initialize Git repository
                        subprocess.run(['git', 'init'], cwd=directory, check=True)
                        
                        # Add all files to Git
                        subprocess.run(['git', 'add', '.'], cwd=directory, check=True)
                        
                        # Initial commit
                        subprocess.run(['git', 'commit', '-m', 'Initial H-SOAR baseline'], cwd=directory, check=True)
                        
                        self.logger.info(f"Git repository initialized in {directory}")
                    else:
                        self.logger.info(f"Git repository already exists in {directory}")
                else:
                    self.logger.warning(f"Directory {directory} does not exist")
            
            except Exception as e:
                self.logger.error(f"Failed to initialize Git repository in {directory}: {e}")
    
    def execute_rollback(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Execute rollback for malicious event"""
        try:
            if not self.enabled:
                return {
                    'success': False,
                    'error': 'Rollback system disabled',
                    'rollback_id': None
                }
            
            filepath = event.get('filepath', '')
            if not filepath:
                return {
                    'success': False,
                    'error': 'No filepath in event',
                    'rollback_id': None
                }
            
            # Find the Git repository for this file
            git_repo = self._find_git_repo(filepath)
            if not git_repo:
                return {
                    'success': False,
                    'error': f'No Git repository found for {filepath}',
                    'rollback_id': None
                }
            
            # Generate rollback ID
            rollback_id = f"rollback_{int(datetime.now().timestamp())}"
            
            # Execute rollback based on event type
            action = event.get('action', '')
            
            if action in ['write', 'modify', 'create']:
                result = self._rollback_file_modification(git_repo, filepath, rollback_id)
            elif action == 'delete':
                result = self._rollback_file_deletion(git_repo, filepath, rollback_id)
            elif action in ['chmod', 'chown']:
                result = self._rollback_file_attributes(git_repo, filepath, rollback_id)
            else:
                result = self._rollback_general(git_repo, filepath, rollback_id)
            
            # Record rollback in history
            rollback_record = {
                'rollback_id': rollback_id,
                'timestamp': datetime.now().isoformat(),
                'filepath': filepath,
                'action': action,
                'git_repo': git_repo,
                'success': result.get('success', False),
                'message': result.get('message', ''),
                'event': event
            }
            
            self.rollback_history.append(rollback_record)
            
            return {
                'success': result.get('success', False),
                'rollback_id': rollback_id,
                'message': result.get('message', ''),
                'error': result.get('error', ''),
                'git_repo': git_repo
            }
        
        except Exception as e:
            self.logger.error(f"Error executing rollback: {e}")
            return {
                'success': False,
                'error': str(e),
                'rollback_id': None
            }
    
    def _find_git_repo(self, filepath: str) -> Optional[str]:
        """Find Git repository for given file path"""
        for repo_dir in self.git_repos.keys():
            if filepath.startswith(repo_dir):
                return repo_dir
        return None
    
    def _rollback_file_modification(self, git_repo: str, filepath: str, rollback_id: str) -> Dict[str, Any]:
        """Rollback file modification"""
        try:
            # Check if file exists in Git history
            result = subprocess.run(
                ['git', 'log', '--oneline', '--', filepath],
                cwd=git_repo,
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0 or not result.stdout.strip():
                return {
                    'success': False,
                    'error': f'File {filepath} not found in Git history',
                    'message': 'Cannot rollback: file not in Git history'
                }
            
            # Create backup of current file
            backup_path = f"{filepath}.backup_{rollback_id}"
            if os.path.exists(filepath):
                shutil.copy2(filepath, backup_path)
                self.logger.info(f"Created backup: {backup_path}")
            
            # Restore file from Git
            subprocess.run(['git', 'checkout', 'HEAD', '--', filepath], cwd=git_repo, check=True)
            
            # Commit the rollback
            subprocess.run(['git', 'add', filepath], cwd=git_repo, check=True)
            subprocess.run(['git', 'commit', '-m', f'H-SOAR rollback: {rollback_id}'], cwd=git_repo, check=True)
            
            return {
                'success': True,
                'message': f'File {filepath} restored from Git history',
                'backup_path': backup_path
            }
        
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'message': f'Failed to rollback file modification: {e}'
            }
    
    def _rollback_file_deletion(self, git_repo: str, filepath: str, rollback_id: str) -> Dict[str, Any]:
        """Rollback file deletion"""
        try:
            # Check if file exists in Git history
            result = subprocess.run(
                ['git', 'log', '--oneline', '--', filepath],
                cwd=git_repo,
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0 or not result.stdout.strip():
                return {
                    'success': False,
                    'error': f'File {filepath} not found in Git history',
                    'message': 'Cannot rollback: file not in Git history'
                }
            
            # Restore deleted file
            subprocess.run(['git', 'checkout', 'HEAD', '--', filepath], cwd=git_repo, check=True)
            
            # Commit the restoration
            subprocess.run(['git', 'add', filepath], cwd=git_repo, check=True)
            subprocess.run(['git', 'commit', '-m', f'H-SOAR restore: {rollback_id}'], cwd=git_repo, check=True)
            
            return {
                'success': True,
                'message': f'Deleted file {filepath} restored from Git history'
            }
        
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'message': f'Failed to restore deleted file: {e}'
            }
    
    def _rollback_file_attributes(self, git_repo: str, filepath: str, rollback_id: str) -> Dict[str, Any]:
        """Rollback file attribute changes"""
        try:
            # Check if file exists in Git history
            result = subprocess.run(
                ['git', 'log', '--oneline', '--', filepath],
                cwd=git_repo,
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0 or not result.stdout.strip():
                return {
                    'success': False,
                    'error': f'File {filepath} not found in Git history',
                    'message': 'Cannot rollback: file not in Git history'
                }
            
            # Restore file attributes from Git
            subprocess.run(['git', 'checkout', 'HEAD', '--', filepath], cwd=git_repo, check=True)
            
            # Commit the rollback
            subprocess.run(['git', 'add', filepath], cwd=git_repo, check=True)
            subprocess.run(['git', 'commit', '-m', f'H-SOAR attribute rollback: {rollback_id}'], cwd=git_repo, check=True)
            
            return {
                'success': True,
                'message': f'File attributes for {filepath} restored from Git history'
            }
        
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'message': f'Failed to rollback file attributes: {e}'
            }
    
    def _rollback_general(self, git_repo: str, filepath: str, rollback_id: str) -> Dict[str, Any]:
        """General rollback for unknown actions"""
        try:
            # Check if file exists in Git history
            result = subprocess.run(
                ['git', 'log', '--oneline', '--', filepath],
                cwd=git_repo,
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0 or not result.stdout.strip():
                return {
                    'success': False,
                    'error': f'File {filepath} not found in Git history',
                    'message': 'Cannot rollback: file not in Git history'
                }
            
            # Restore file from Git
            subprocess.run(['git', 'checkout', 'HEAD', '--', filepath], cwd=git_repo, check=True)
            
            # Commit the rollback
            subprocess.run(['git', 'add', filepath], cwd=git_repo, check=True)
            subprocess.run(['git', 'commit', '-m', f'H-SOAR general rollback: {rollback_id}'], cwd=git_repo, check=True)
            
            return {
                'success': True,
                'message': f'File {filepath} restored from Git history'
            }
        
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'message': f'Failed to rollback file: {e}'
            }
    
    def create_baseline(self, directory: str) -> Dict[str, Any]:
        """Create baseline for directory"""
        try:
            if directory not in self.git_repos:
                return {
                    'success': False,
                    'error': f'Directory {directory} not configured for Git tracking'
                }
            
            # Add all files to Git
            subprocess.run(['git', 'add', '.'], cwd=directory, check=True)
            
            # Create baseline commit
            subprocess.run(['git', 'commit', '-m', f'H-SOAR baseline: {datetime.now().isoformat()}'], cwd=directory, check=True)
            
            return {
                'success': True,
                'message': f'Baseline created for {directory}',
                'timestamp': datetime.now().isoformat()
            }
        
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'message': f'Failed to create baseline: {e}'
            }
    
    def get_rollback_history(self) -> List[Dict[str, Any]]:
        """Get rollback history"""
        return self.rollback_history
    
    def get_git_status(self, directory: str) -> Dict[str, Any]:
        """Get Git status for directory"""
        try:
            if directory not in self.git_repos:
                return {
                    'success': False,
                    'error': f'Directory {directory} not configured for Git tracking'
                }
            
            # Get Git status
            result = subprocess.run(['git', 'status', '--porcelain'], cwd=directory, capture_output=True, text=True)
            
            if result.returncode != 0:
                return {
                    'success': False,
                    'error': f'Git status failed: {result.stderr}'
                }
            
            # Parse status
            modified_files = []
            untracked_files = []
            
            for line in result.stdout.strip().split('\n'):
                if line:
                    status = line[:2]
                    filename = line[3:]
                    
                    if status[0] in ['M', 'A', 'D']:
                        modified_files.append(filename)
                    elif status[0] == '?':
                        untracked_files.append(filename)
            
            return {
                'success': True,
                'modified_files': modified_files,
                'untracked_files': untracked_files,
                'total_changes': len(modified_files) + len(untracked_files)
            }
        
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_status(self) -> Dict[str, Any]:
        """Get rollback system status"""
        return {
            'available': self.enabled,
            'auto_rollback': self.auto_rollback,
            'rollback_threshold': self.rollback_threshold,
            'git_repos': list(self.git_repos.keys()),
            'rollback_count': len(self.rollback_history),
            'last_rollback': self.rollback_history[-1] if self.rollback_history else None
        }
