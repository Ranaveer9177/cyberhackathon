import subprocess
import os
from flask import Flask, request

app = Flask(__name__)

@app.route("/api/ping", methods=["POST"])
def ping_host():
    target = request.json.get("host", "127.0.0.1")
    # Vulnerable: shell=True command injection
    result = subprocess.check_output(f"ping -c 1 {target}", shell=True)
    return {"output": result.decode()}

@app.route("/api/nslookup", methods=["GET"])
def lookup_domain():
    domain = request.args.get("domain", "localhost")
    # Vulnerable: os.system command injection
    code = os.system("nslookup " + domain)
    return {"status": code}
