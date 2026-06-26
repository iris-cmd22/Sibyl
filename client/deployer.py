import os
import subprocess
import sys
import tempfile
from pathlib import Path

class Deployer:
    def __init__(self):
        self.root = Path(__file__).resolve().parent.parent
        self.ansible_playbook = self.root / "ansible" / "playbook.yml"
        self.inventory = self.root / "ansible" / "inventory.ini"

    def deploy_remote(self, ip_address: str, ssh_user: str, sudo_pass: str):
        # Scrittura inventory (aggiungi la password qui se vuoi, o usa -e)
        with open(self.inventory, "w") as f:
            f.write(f"[mcp_servers]\n{ip_address} ansible_user={ssh_user}")

        print(f"🚀 Lancio Ansible...")
        
        cmd = [
            "ansible-playbook", 
            "-i", str(self.inventory), 
            str(self.ansible_playbook),
            "-e", f"ansible_become_pass={sudo_pass}" # Passaggio diretto della password
        ]
        
        subprocess.run(cmd, check=True)
          