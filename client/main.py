import getpass 
from client.deployer import Deployer

def main():
    print("--- Sibyl Control Plane ---")
    ip = input("IP della VM: ").strip()
    user = input("Username SSH: ").strip()
    # getpass nasconde i caratteri mentre scrivi
    sudo_pass = getpass.getpass("Password sudo: ") 
    
    deployer = Deployer()
    deployer.deploy_remote(ip, user, sudo_pass)

if __name__ == "__main__":
    main()