import os
import requests
from dotenv import load_dotenv

load_dotenv()

JIRA_URL = os.getenv("JIRA_URL")
JIRA_AUTH = os.getenv("JIRA_AUTH")

def delete_attachment(attachment_id):
    """Deletes a Jira attachment."""
    url = f"{JIRA_URL}/rest/api/3/attachment/{attachment_id}"
    headers = {
        "Authorization": f"Basic {JIRA_AUTH}",
        "Accept": "application/json"
    }

    response = requests.delete(url, headers=headers)
    
    if response.status_code == 204:
        print(f"Deleted attachment {attachment_id}")
        return True
    else:
        print(f"Failed to delete {attachment_id}: {response.text}")
        return False
