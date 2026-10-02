import os
import requests
from dotenv import load_dotenv

load_dotenv()
token = os.getenv("META_PAGE_ACCESS_TOKEN")

if not token:
    print("Error: META_PAGE_ACCESS_TOKEN is missing in .env")
    exit(1)

print("1. Subscribing Instagram account to Webhook messages...")
url = "https://graph.instagram.com/v21.0/me/subscribed_apps"
params = {
    "subscribed_fields": "messages",
    "access_token": token
}

res = requests.post(url, params=params)
print(f"Status Code: {res.status_code}")
print(f"Response: {res.text}")

print("\n2. Checking current subscriptions...")
res_check = requests.get(url, params={"access_token": token})
print(f"Status Code: {res_check.status_code}")
print(f"Current Subscriptions: {res_check.text}")
