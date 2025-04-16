# utils/quarantine.py

import subprocess

def block_ip(ip):
    """
    Blocks incoming traffic from a specified IP using iptables.
    """
    try:
        # Append an iptables rule to drop traffic from the given IP.
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        print(f"IP {ip} has been blocked successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error blocking IP {ip}: {e}")

if __name__ == "__main__":
    # Example usage: block a specific IP.
    test_ip = "192.168.51.100"
    block_ip(test_ip)
