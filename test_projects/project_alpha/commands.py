import subprocess


def ping_host(host):
    cmd = "ping -c 1 " + host
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    out, _ = proc.communicate()
    return out.decode()
