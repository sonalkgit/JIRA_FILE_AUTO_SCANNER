import base64
import os
from dotenv import load_dotenv

load_dotenv()

JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN")

email = ""  # Replace with your Jira email
api_token = JIRA_API_TOKEN  # Replace with your Jira API token
auth_string = f"{email}:{api_token}"
encoded_auth = base64.b64encode(auth_string.encode()).decode()

print("JIRA_AUTH =", encoded_auth)
