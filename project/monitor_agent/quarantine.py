import subprocess

def block_ip(ip):
    """
    Blocks incoming traffic from a specified IP using iptables, avoiding duplicates.
    """
    try:
        result = subprocess.run(
            ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        if result.returncode == 0:
            print(f"IP {ip} is already blocked.")
        else:
            result = subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            print(f"IP {ip} has been blocked successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error while blocking IP {ip}: {e.stderr.decode()}")

if __name__ == "__main__":
    # Example usage
    test_ip = "192.168.51.100"
    block_ip(test_ip)