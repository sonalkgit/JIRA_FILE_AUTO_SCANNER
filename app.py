from flask import Flask, request, jsonify
import threading
import os
from dotenv import load_dotenv
from utils import verify_jira_signature
from scanner import process_attachment

load_dotenv()
app = Flask(__name__)

JIRA_SECRET = os.getenv("JIRA_SECRET")

@app.route("/webhook", methods=["POST", "GET"])
def webhook():
    """Handles incoming Jira webhooks for attachment events."""
    print("dddddddddddddddddddddddddddddd")
    if not verify_jira_signature(request, JIRA_SECRET):
        return jsonify({"error": "Unauthorized"}), 403

    data = request.json
    issue_key = data["issue"]["key"]
    attachments = data["issue"]["fields"]["attachment"]
    # Process attachments asynchronously
    for attachment in attachments:
        threading.Thread(target=process_attachment, args=(issue_key, attachment)).start()

    return jsonify({"message": "Processing started"}), 200

if __name__ == "__main__":
    app.run(debug=True, port=5000)
