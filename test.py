import os
import subprocess
import time
from render_sdk import Workflows

app = Workflows()

@app.task()
def start_tailscale_rdp():
    """
    Install xrdp + XFCE, then join Tailscale so RDP is reachable via Tailnet.
    The task will keep running to maintain the Tailscale connection.
    """

    # 1. Install system packages (xrdp, desktop, and Tailscale dependencies)
    subprocess.run(
        "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y "
        "xfce4 xfce4-goodies xrdp curl",
        shell=True,
        check=True,
    )

    # 2. Configure xrdp to start XFCE
    with open("/etc/xrdp/startwm.sh", "w") as f:
        f.write("#!/bin/sh\n")
        f.write("startxfce4\n")
    subprocess.run("chmod +x /etc/xrdp/startwm.sh", shell=True)

    # 3. Start xrdp service
    subprocess.run("service xrdp start", shell=True, check=True)

    # 4. Install Tailscale
    #    The official script uses sudo; in Render workflows, sudo may not be available,
    #    but the user is often root. If sudo fails, fall back to running without sudo.
    try:
        subprocess.run(
            "curl -fsSL https://tailscale.com/install.sh | sh",
            shell=True,
            check=True,
        )
    except subprocess.CalledProcessError:
        # If sudo is missing, try running without it (if we are root)
        subprocess.run(
            "curl -fsSL https://tailscale.com/install.sh | bash",
            shell=True,
            check=True,
        )

    # 5. Authenticate with Tailscale using your auth key
    auth_key = os.environ.get("TAILSCALE_AUTH_KEY", "YOUR_TAILSCALE_AUTH_KEY")
    subprocess.run(
        f"tailscale up --auth-key={auth_key} --accept-routes",
        shell=True,
        check=True,
    )

    # 6. Give Tailscale a moment to obtain an IP
    time.sleep(5)

    # 7. Print the Tailscale IP for the user
    try:
        ip_output = subprocess.run(
            "tailscale ip -4",
            shell=True,
            capture_output=True,
            text=True,
        )
        tailscale_ip = ip_output.stdout.strip()
        print(f"\n✅ Tailscale node is online. Connect to RDP at: {tailscale_ip}:3389")
    except Exception:
        print("Could not retrieve Tailscale IP. Check Tailscale status with: tailscale status")

    # 8. Keep the task alive (so Tailscale and xrdp continue running)
    print("\nRDP server running. The workflow will stay active until you stop it or the task expires.")
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("Shutting down...")

if __name__ == "__main__":
    app.start()
