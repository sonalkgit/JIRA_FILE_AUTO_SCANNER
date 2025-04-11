import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB = os.getenv("MONGO_DB")

client = MongoClient(MONGO_URI)
db = client[MONGO_DB]
scanned_files = db.attachments

def file_already_scanned(file_hash):
    """Checks if the file was already scanned."""
    return scanned_files.find_one({"file_hash": file_hash}) is not None

def save_file_scan(file_hash, file_name, is_malicious):
    """Saves scan result to database."""
    print(f"Attempting to insert: file_hash={file_hash}, file_name={file_name}, is_malicious={is_malicious}")
    
    try:
        result = scanned_files.insert_one({
            "file_hash": file_hash,
            "file_name": file_name,
            "is_malicious": is_malicious
        })
        print(f"Inserted successfully with ID: {result.inserted_id}")
    except Exception as e:
        print(f"Error inserting document: {e}")

