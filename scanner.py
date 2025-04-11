import requests
import os
import hashlib
import time
from database import file_already_scanned, save_file_scan
from jira import delete_attachment
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth


load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


def scan_url_virustotal(file_url):
    """Scans the Jira file URL using VirusTotal."""
    url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    data = {"url": file_url}

    response = requests.post(url, headers=headers, data=data)

    if response.status_code == 200:
        analysis_id = response.json()["data"]["id"]
        print(f"Scan request successful. Analysis ID: {analysis_id}")
        return analysis_id
    else:
        print("VirusTotal URL scan failed:", response.text)
        return None


def get_scan_result(analysis_id):
    """Fetches the scan result using the analysis ID."""
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    while True:
        response = requests.get(url, headers=headers)
        print("jjjjjjjjjjjjjjjjjjjjj")
        if response.status_code == 200:
            result = response.json()
            status = result["data"]["attributes"]["status"]

            if status == "completed":
                return result
            else:
                print(" Scan is still in progress. Waiting...")
                time.sleep(5)  # Wait 5 seconds before checking again
        else:
            print("Failed to fetch scan results:", response.text)
            return None


def process_scan_response(scan_result):
    """Checks if a file is malicious based on VirusTotal scan results."""
    stats = scan_result["data"]["attributes"]["stats"]
    malicious_count = stats.get("malicious", 0)

    return malicious_count > 0


def get_file_hash(file_url):
    """Download the file and compute its SHA-256 hash with authentication."""
    
    JIRA_EMAIL = os.getenv("JIRA_EMAIL")  # Your Jira email
    JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN")  # Your Jira API token
    
    # Basic Auth using email and API token
    auth = HTTPBasicAuth(JIRA_EMAIL, JIRA_API_TOKEN)

    response = requests.get(file_url, auth=auth)  # Authenticate request

    if response.status_code != 200:
        print(f"Failed to download file: {response.status_code} - {response.text}")
        return None  

    file_content = response.content
    return hashlib.sha256(file_content).hexdigest()


def process_attachment(issue_key, attachment):
    """Processes a Jira attachment by scanning and deleting if malicious."""
    file_url = attachment["content"]
    file_name = attachment["filename"]

    print(f"Processing file: {file_name}")

    # Generate a unique hash for the file
    file_hash = get_file_hash(file_url)
    if not file_hash:
        print(f"Failed to download {file_name}. Skipping...")
        return

    scanned_file = file_already_scanned(file_hash)

    if scanned_file:
        if scanned_file["is_malicious"]:
            print(f"{file_name} was previously marked as MALICIOUS. Deleting from new issue...")
            delete_attachment(attachment["id"])  # Delete immediately
        else:
            print(f"{file_name} was previously scanned and is CLEAN. Skipping re-scan.")
        return 
    #  Check if this file hash was already scanned
    if file_already_scanned(file_hash):  
        print(f"Skipping {file_name}, already scanned before.")
        return

    analysis_id = scan_url_virustotal(file_url)
    
    if not analysis_id:
        print(f"Failed to scan {file_name}. Skipping...")
        return

    scan_result = get_scan_result(analysis_id)
    
    if scan_result and process_scan_response(scan_result):
        print(f"File {file_name} is MALICIOUS. Deleting...")
        delete_attachment(attachment["id"])
        save_file_scan(file_hash, file_name, is_malicious=True)  # Store hash instead of file_id
    else:
        print(f"File {file_name} is CLEAN.")
        save_file_scan(file_hash, file_name, is_malicious=False) 