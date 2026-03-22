import os
import subprocess
import time
import sys
from render_sdk import Workflows

app = Workflows()

def run_cmd(cmd, check=False):
    """Run a command and print output in real time."""
    print(f"\n$ {cmd}")
    # Use Popen to stream output
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in process.stdout:
        print(line, end='')
    process.wait()
    if check and process.returncode != 0:
        raise subprocess.CalledProcessError(process.returncode, cmd)
    return process.returncode

@app.task()
def start_tailscale_rdp():
    # 1. Check environment
    print("=== Environment Info ===")
    run_cmd("cat /etc/os-release")
    run_cmd("uname -a")
    run_cmd("whoami")

    # 2. Update package lists with retries
    for attempt in range(3):
        print(f"\n--- APT update attempt {attempt+1} ---")
        ret = run_cmd("apt-get update --fix-missing --allow-releaseinfo-change -y")
        if ret == 0:
            print("APT update succeeded.")
            break
        print("APT update failed. Retrying in 5 seconds...")
        time.sleep(5)
    else:
        raise Exception("APT update failed after 3 attempts.")

    # 3. Install packages one by one
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
            ret = run_cmd(f"DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {pkg}")
            if ret == 0:
                installed = True
                break
        if not installed:
            raise Exception(f"Failed to install {display_name}")

    # 4. Configure xrdp
    with open("/etc/xrdp/startwm.sh", "w") as f:
        f.write("#!/bin/sh\nstartxfce4\n")
    run_cmd("chmod +x /etc/xrdp/startwm.sh")
    run_cmd("service xrdp start")

    # 5. Install Tailscale
    run_cmd("curl -fsSL https://tailscale.com/install.sh | sh")
    auth_key = os.environ.get("TAILSCALE_AUTH_KEY", "YOUR_AUTH_KEY_HERE")
    run_cmd(f"tailscale up --auth-key={auth_key} --accept-routes")

    # 6. Get Tailscale IP
    time.sleep(5)
    run_cmd("tailscale ip -4")

    print("\n✅ RDP server running. Keep this task alive.")
    while True:
        time.sleep(60)

if __name__ == "__main__":
    app.start()
