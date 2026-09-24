from flask import Flask, request, jsonify

app = Flask(__name__)

# Vulnerable: Webhook receiver without signature verification (VG-WEBHOOK-001)
@app.route("/api/v1/webhook", methods=["POST"])
def handle_incoming_webhook():
    event_data = request.json
    event_type = event_data.get("type")
    
    # Process event directly without verifying signature or HMAC header
    if event_type == "payment.succeeded":
        process_payment(event_data)
        
    return jsonify({"status": "received"}), 200

def process_payment(data):
    pass
