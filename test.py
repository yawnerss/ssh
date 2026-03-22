import os
import subprocess
import time
from render_sdk import Workflows

app = Workflows()

def run_cmd(cmd, check=True, capture=True):
    """Run a shell command and print output."""
    print(f"$ {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=capture, text=True)
    if capture:
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
    if check and result.returncode != 0:
        print(f"Command failed with exit code {result.returncode}")
        raise subprocess.CalledProcessError(result.returncode, cmd)
    return result

@app.task()
def start_tailscale_rdp():
    """
    Install xrdp + XFCE, then join Tailscale.
    The task will keep running to maintain the connection.
    """
    # 1. Print environment info (for debugging)
    run_cmd("cat /etc/os-release", check=False)
    run_cmd("uname -a", check=False)
    run_cmd("whoami", check=False)

    # 2. Update package lists with retries and fixes
    for attempt in range(3):
        print(f"\n=== APT update attempt {attempt+1} ===")
        ret = run_cmd(
            "apt-get update --fix-missing --allow-releaseinfo-change -y",
            check=False,
            capture=False,
        )
        if ret.returncode == 0:
            print("APT update succeeded.")
            break
        else:
            print("APT update failed. Retrying in 5 seconds...")
            time.sleep(5)
    else:
        raise Exception("Failed to update APT after 3 attempts.")

    # 3. Install required packages (with fallback for missing packages)
    packages = ["xfce4", "xfce4-goodies", "xrdp", "curl"]
    for pkg in packages:
        print(f"\nInstalling {pkg}...")
        ret = run_cmd(
            f"DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {pkg}",
            check=False,
            capture=False,
        )
        if ret.returncode != 0:
            # Try with different package name if it fails (e.g., for Debian vs Ubuntu)
            if pkg == "xfce4":
                print("xfce4 not found, trying task-xfce-desktop...")
                run_cmd("apt-get install -y task-xfce-desktop", capture=False)
            elif pkg == "xfce4-goodies":
                print("xfce4-goodies not found, skipping...")
                continue
            else:
                raise Exception(f"Failed to install {pkg}")

    # 4. Configure xrdp to start XFCE
    with open("/etc/xrdp/startwm.sh", "w") as f:
        f.write("#!/bin/sh\n")
        f.write("startxfce4\n")
    run_cmd("chmod +x /etc/xrdp/startwm.sh", capture=False)

    # 5. Start xrdp service
    run_cmd("service xrdp start", check=False, capture=False)

    # 6. Install Tailscale (using official script)
    run_cmd("curl -fsSL https://tailscale.com/install.sh | sh", capture=False)

    # 7. Authenticate with Tailscale
    auth_key = os.environ.get("TAILSCALE_AUTH_KEY", "YOUR_TAILSCALE_AUTH_KEY")
    run_cmd(f"tailscale up --auth-key={auth_key} --accept-routes", capture=False)

    # 8. Wait for Tailscale to get an IP
    time.sleep(5)

    # 9. Print Tailscale IP
    ip_result = run_cmd("tailscale ip -4", capture=True, check=False)
    if ip_result.returncode == 0:
        tailscale_ip = ip_result.stdout.strip()
        print(f"\n✅ Tailscale node online. Connect RDP at: {tailscale_ip}:3389")
    else:
        print("Could not retrieve Tailscale IP. Check with: tailscale status")

    # 10. Keep the task alive
    print("\nRDP server running. Press Ctrl+C to stop (or task will expire).")
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("Shutting down...")

if __name__ == "__main__":
    app.start()
