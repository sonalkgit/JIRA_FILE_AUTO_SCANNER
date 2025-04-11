import os
from pymongo import MongoClient
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get MongoDB credentials
MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB = os.getenv("MONGO_DB")

# Connect to MongoDB
try:
    client = MongoClient(MONGO_URI)
    db = client[MONGO_DB]

    # Test connection
    print("Connected to MongoDB!")

    # Check existing collections
    print("Collections:", db.attachments)

except Exception as e:
    print("Connection failed:", e)
