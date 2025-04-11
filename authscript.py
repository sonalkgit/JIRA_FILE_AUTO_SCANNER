import requests
import os
from dotenv import load_dotenv

load_dotenv()

JIRA_URL = os.getenv("JIRA_URL")
JIRA_AUTH = os.getenv("JIRA_AUTH")

url = f"{JIRA_URL}/rest/api/3/myself"

headers = {
    "Authorization": f"Basic {JIRA_AUTH}",
    "Accept": "application/json"
}

response = requests.get(url, headers=headers)

if response.status_code == 200:
    print("Jira authentication successful!")
else:
    print("Jira authentication failed:", response.text)
