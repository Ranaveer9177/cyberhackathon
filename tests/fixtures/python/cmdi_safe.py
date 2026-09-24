import subprocess

def run_backup(target):
    subprocess.run(["tar", "-czf", "backup.tar.gz", target], check=True)
