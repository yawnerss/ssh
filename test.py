import os
import subprocess
import time
import sys
from render_sdk import Workflows

app = Workflows()

def run_cmd(cmd, check=False):
    """Run a shell command, print output in real time, return exit code."""
    print(f"\n$ {cmd}")
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in process.stdout:
        print(line, end='')
    process.wait()
    if check and process.returncode != 0:
        raise subprocess.CalledProcessError(process.returncode, cmd)
    return process.returncode

def fix_apt_permissions():
    """Create missing apt directories and set permissions."""
    print("=== Fixing apt permissions ===")
    # Create /var/lib/apt/lists/partial if missing
    if not os.path.exists("/var/lib/apt/lists/partial"):
        print("Creating /var/lib/apt/lists/partial...")
        run_cmd("mkdir -p /var/lib/apt/lists/partial")
        run_cmd("chmod 755 /var/lib/apt/lists/partial")
    # Ensure /etc/apt/sources.list exists (Ubuntu 22.04 mirrors)
    if not os.path.exists("/etc/apt/sources.list") or os.path.getsize("/etc/apt/sources.list") == 0:
        print("Writing /etc/apt/sources.list...")
        with open("/etc/apt/sources.list", "w") as f:
            f.write("deb http://archive.ubuntu.com/ubuntu jammy main universe\n")
            f.write("deb http://archive.ubuntu.com/ubuntu jammy-updates main universe\n")
            f.write("deb http://archive.ubuntu.com/ubuntu jammy-security main universe\n")

def try_with_sudo(cmd):
    """Attempt to run command with sudo if available; fallback to direct execution."""
    # Check if sudo is available
    ret = run_cmd("which sudo", check=False)
    if ret == 0:
        return run_cmd(f"sudo {cmd}", check=False)
    else:
        return run_cmd(cmd, check=False)

@app.task()
def start_tailscale_rdp():
    # 1. Show environment info
    print("=== Environment Info ===")
    run_cmd("cat /etc/os-release", check=False)
    run_cmd("uname -a", check=False)
    run_cmd("whoami", check=False)
    run_cmd("id", check=False)

    # 2. Fix apt permissions and sources
    fix_apt_permissions()

    # 3. Update package lists (with retries)
    for attempt in range(3):
        print(f"\n--- APT update attempt {attempt+1} ---")
        ret = try_with_sudo("apt-get update --fix-missing --allow-releaseinfo-change -y")
        if ret == 0:
            print("APT update succeeded.")
            break
        print("APT update failed. Retrying in 5 seconds...")
        time.sleep(5)
    else:
        raise Exception("APT update failed after 3 attempts.")

    # 4. Install packages one by one
    packages_to_try = [
        ("xfce4", ["xfce4", "task-xfce-desktop"]),
        ("xfce4-goodies", ["xfce4-goodies"]),
        ("xrdp", ["xrdp"]),
        ("curl", ["curl"])
    ]

    for display_name, pkg_names in packages_to_try:
        installed = False
        for pkg in pkg_names:
            print(f"\nTrying to install {pkg}...")
            ret = try_with_sudo(f"DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {pkg}")
            if ret == 0:
                installed = True
                break
        if not installed:
            raise Exception(f"Failed to install {display_name}")

    # 5. Configure xrdp
    with open("/etc/xrdp/startwm.sh", "w") as f:
        f.write("#!/bin/sh\nstartxfce4\n")
    try_with_sudo("chmod +x /etc/xrdp/startwm.sh")
    try_with_sudo("service xrdp start")

    # 6. Install Tailscale
    print("\n=== Installing Tailscale ===")
    try_with_sudo("curl -fsSL https://tailscale.com/install.sh | sh")

    # 7. Authenticate with Tailscale
    auth_key = os.environ.get("TAILSCALE_AUTH_KEY", "YOUR_AUTH_KEY_HERE")
    try_with_sudo(f"tailscale up --auth-key={auth_key} --accept-routes")

    # 8. Get Tailscale IP
    time.sleep(5)
    try_with_sudo("tailscale ip -4")

    print("\n✅ RDP server running. Keep this task alive.")
    while True:
        time.sleep(60)

if __name__ == "__main__":
    app.start()
