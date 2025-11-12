#!/usr/bin/env python3
"""
Auditd Collector for H-SOAR HIDS
Collects and parses auditd logs for file system and process monitoring
"""

import os
import json
import logging
import subprocess
import threading
import queue
from typing import Dict, List, Any, Optional
from datetime import datetime
import re

class AuditdCollector:
    """
    Collects auditd events and parses them for HIDS analysis
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize auditd collector"""
        self.config = config
        self.logger = logging.getLogger('AuditdCollector')
        self.log_file = config.get('log_file', '/var/log/audit/audit.log')
        self.rules_file = config.get('rules_file', '/etc/audit/rules.d/hids.rules')
        self.is_collecting = False
        self.event_queue = queue.Queue()
        self.collection_thread = None
        
        # Event patterns for parsing
        self.event_patterns = {
            'file_access': re.compile(r'type=SYSCALL.*syscall=(\d+).*comm="([^"]+)".*name="([^"]+)".*key="([^"]+)"'),
            'file_write': re.compile(r'type=SYSCALL.*syscall=(\d+).*comm="([^"]+)".*name="([^"]+)".*key="([^"]+)".*exit=0'),
            'process_exec': re.compile(r'type=SYSCALL.*syscall=59.*comm="([^"]+)".*exe="([^"]+)".*key="([^"]+)"'),
            'file_attr': re.compile(r'type=SYSCALL.*syscall=(\d+).*comm="([^"]+)".*name="([^"]+)".*key="([^"]+)"'),
            'network': re.compile(r'type=SYSCALL.*syscall=(\d+).*comm="([^"]+)".*key="([^"]+)"'),
            'privilege': re.compile(r'type=SYSCALL.*syscall=(\d+).*comm="([^"]+)".*key="([^"]+)"')
        }
    
    def start_collection(self):
        """Start auditd event collection"""
        self.logger.info("Starting auditd event collection...")
        self.is_collecting = True
        
        # Start collection thread
        self.collection_thread = threading.Thread(target=self._collect_events)
        self.collection_thread.daemon = True
        self.collection_thread.start()
        
        self.logger.info("Auditd collection started")
    
    def stop_collection(self):
        """Stop auditd event collection"""
        self.logger.info("Stopping auditd event collection...")
        self.is_collecting = False
        
        if self.collection_thread:
            self.collection_thread.join(timeout=5)
        
        self.logger.info("Auditd collection stopped")
    
    def _collect_events(self):
        """Main event collection loop"""
        try:
            # Use ausearch to get real-time events
            cmd = ['ausearch', '-i', '-k', 'hids_fim,hids_process,hids_attr,hids_network,hids_priv']
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            while self.is_collecting:
                line = process.stdout.readline()
                if line:
                    event = self._parse_auditd_event(line.strip())
                    if event:
                        self.event_queue.put(event)
                elif process.poll() is not None:
                    break
            
        except Exception as e:
            self.logger.error(f"Error in auditd collection: {e}")
    
    def _parse_auditd_event(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse auditd event line"""
        try:
            # Extract basic event information
            event = {
                'raw_line': line,
                'timestamp': datetime.now().isoformat(),
                'event_type': 'unknown',
                'filepath': None,
                'process': None,
                'user': None,
                'action': None,
                'key': None
            }
            
            # Extract timestamp
            timestamp_match = re.search(r'msg=audit\((\d+\.\d+):(\d+)\)', line)
            if timestamp_match:
                event['timestamp'] = datetime.fromtimestamp(float(timestamp_match.group(1))).isoformat()
            
            # Extract user
            user_match = re.search(r'uid=(\d+)', line)
            if user_match:
                event['user'] = user_match.group(1)
            
            # Extract process
            process_match = re.search(r'comm="([^"]+)"', line)
            if process_match:
                event['process'] = process_match.group(1)
            
            # Extract file path
            file_match = re.search(r'name="([^"]+)"', line)
            if file_match:
                event['filepath'] = file_match.group(1)
            
            # Extract key
            key_match = re.search(r'key="([^"]+)"', line)
            if key_match:
                event['key'] = key_match.group(1)
            
            # Determine event type and action
            if 'hids_fim' in line:
                event['event_type'] = 'file_integrity'
                if 'syscall=2' in line:  # open
                    event['action'] = 'open'
                elif 'syscall=257' in line:  # openat
                    event['action'] = 'open'
                elif 'syscall=1' in line:  # write
                    event['action'] = 'write'
                elif 'syscall=82' in line:  # rename
                    event['action'] = 'rename'
                elif 'syscall=83' in line:  # truncate
                    event['action'] = 'truncate'
                elif 'syscall=87' in line:  # unlink
                    event['action'] = 'delete'
            
            elif 'hids_process' in line:
                event['event_type'] = 'process_execution'
                event['action'] = 'execute'
            
            elif 'hids_attr' in line:
                event['event_type'] = 'file_attribute'
                if 'syscall=90' in line:  # chmod
                    event['action'] = 'chmod'
                elif 'syscall=92' in line:  # chown
                    event['action'] = 'chown'
            
            elif 'hids_network' in line:
                event['event_type'] = 'network'
                if 'syscall=49' in line:  # bind
                    event['action'] = 'bind'
                elif 'syscall=42' in line:  # connect
                    event['action'] = 'connect'
            
            elif 'hids_priv' in line:
                event['event_type'] = 'privilege'
                if 'syscall=105' in line:  # setuid
                    event['action'] = 'setuid'
                elif 'syscall=106' in line:  # setgid
                    event['action'] = 'setgid'
            
            return event
        
        except Exception as e:
            self.logger.warning(f"Could not parse auditd event: {e}")
            return None
    
    def get_latest_events(self, max_events: int = 100) -> List[Dict[str, Any]]:
        """Get latest events from queue"""
        events = []
        
        try:
            while len(events) < max_events and not self.event_queue.empty():
                event = self.event_queue.get_nowait()
                events.append(event)
        except queue.Empty:
            pass
        
        return events
    
    def get_events_by_type(self, event_type: str, max_events: int = 100) -> List[Dict[str, Any]]:
        """Get events filtered by type"""
        all_events = self.get_latest_events(max_events * 2)
        filtered_events = [e for e in all_events if e.get('event_type') == event_type]
        return filtered_events[:max_events]
    
    def get_file_events(self, filepath: str, max_events: int = 100) -> List[Dict[str, Any]]:
        """Get events for specific file"""
        all_events = self.get_latest_events(max_events * 2)
        filtered_events = [e for e in all_events if e.get('filepath') == filepath]
        return filtered_events[:max_events]
    
    def get_process_events(self, process: str, max_events: int = 100) -> List[Dict[str, Any]]:
        """Get events for specific process"""
        all_events = self.get_latest_events(max_events * 2)
        filtered_events = [e for e in all_events if e.get('process') == process]
        return filtered_events[:max_events]
    
    def get_events_summary(self) -> Dict[str, Any]:
        """Get summary of recent events"""
        events = self.get_latest_events(1000)
        
        summary = {
            'total_events': len(events),
            'event_types': {},
            'top_processes': {},
            'top_files': {},
            'top_users': {},
            'recent_actions': {}
        }
        
        for event in events:
            # Count event types
            event_type = event.get('event_type', 'unknown')
            summary['event_types'][event_type] = summary['event_types'].get(event_type, 0) + 1
            
            # Count processes
            process = event.get('process', 'unknown')
            summary['top_processes'][process] = summary['top_processes'].get(process, 0) + 1
            
            # Count files
            filepath = event.get('filepath', 'unknown')
            if filepath != 'unknown':
                summary['top_files'][filepath] = summary['top_files'].get(filepath, 0) + 1
            
            # Count users
            user = event.get('user', 'unknown')
            summary['top_users'][user] = summary['top_users'].get(user, 0) + 1
            
            # Count actions
            action = event.get('action', 'unknown')
            summary['recent_actions'][action] = summary['recent_actions'].get(action, 0) + 1
        
        return summary
    
    def get_status(self) -> Dict[str, Any]:
        """Get collector status"""
        return {
            'active': self.is_collecting,
            'log_file': self.log_file,
            'rules_file': self.rules_file,
            'queue_size': self.event_queue.qsize(),
            'collection_thread_active': self.collection_thread and self.collection_thread.is_alive()
        }
    
    def test_auditd_connection(self) -> bool:
        """Test auditd connection"""
        try:
            # Test if auditd is running
            result = subprocess.run(['auditctl', '-s'], capture_output=True, text=True)
            if result.returncode == 0:
                self.logger.info("Auditd connection test successful")
                return True
            else:
                self.logger.error(f"Auditd connection test failed: {result.stderr}")
                return False
        except Exception as e:
            self.logger.error(f"Auditd connection test error: {e}")
            return False
