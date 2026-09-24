import os
import subprocess

def run_backup(target):
    cmd = "tar -czf backup.tar.gz " + target
    os.system(cmd)

def run_shell(param):
    subprocess.Popen(f"echo {param}", shell=True)
