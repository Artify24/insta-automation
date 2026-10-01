import os
import hmac
import hashlib
import json
import logging
from typing import Optional
from fastapi import FastAPI, Request, Response, HTTPException, Query
from fastapi.responses import PlainTextResponse
import requests
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="Aegis Instagram Lead Bot", version="1.0.0")

@app.middleware("http")
async def normalize_vercel_path(request: Request, call_next):
    """Normalizes Vercel serverless path rewrites so all routes match cleanly."""
    invoke_path = request.headers.get("x-invoke-path") or request.headers.get("x-matched-path")
    if invoke_path and not invoke_path.startswith("/api/index.py"):
        request.scope["path"] = invoke_path
    else:
        for prefix in ["/api/index.py", "/api/index"]:
            if request.scope.get("path", "").startswith(prefix):
                remainder = request.scope["path"][len(prefix):]
                request.scope["path"] = remainder if remainder else "/"
                break
    response = await call_next(request)
    return response

# Meta Configuration
VERIFY_TOKEN = os.getenv("META_VERIFY_TOKEN", "aegis_secure_verify_token_2026")
APP_SECRET = os.getenv("META_APP_SECRET", "")
PAGE_ACCESS_TOKEN = os.getenv("META_PAGE_ACCESS_TOKEN", "")
GRAPH_API_VERSION = os.getenv("META_GRAPH_API_VERSION", "v21.0")

def verify_meta_signature(payload: bytes, signature_header: Optional[str]) -> bool:
    """Verifies HMAC SHA-256 signature from Meta to prevent spoofing."""
    if not APP_SECRET:
        return True
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected_hash = signature_header.split("=")[1]
    calculated_hash = hmac.new(
        APP_SECRET.encode("utf-8"),
        payload,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(calculated_hash, expected_hash)

def send_instagram_message(recipient_id: str, text: str):
    """Sends reply via Instagram Graph API using the Access Token."""
    if not PAGE_ACCESS_TOKEN:
        logger.warning(f"No access token configured. Skipping reply to {recipient_id}")
        return

    # Try graph.instagram.com first (for IGAA tokens), fallback to graph.facebook.com
    endpoints = [
        f"https://graph.instagram.com/{GRAPH_API_VERSION}/me/messages",
        f"https://graph.facebook.com/{GRAPH_API_VERSION}/me/messages",
    ]

    payload = {
        "recipient": {"id": recipient_id},
        "message": {"text": text}
    }
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {PAGE_ACCESS_TOKEN}"
    }

    for url in endpoints:
        try:
            res = requests.post(url, json=payload, headers=headers, params={"access_token": PAGE_ACCESS_TOKEN}, timeout=10)
            res_data = res.json()
            if res.status_code == 200:
                logger.info(f"Successfully sent reply to {recipient_id}: {res_data}")
                return
            else:
                logger.warning(f"Failed via {url} (code {res.status_code}): {res_data}")
        except Exception as e:
            logger.error(f"Error sending message via {url}: {e}")

def generate_lead_response(incoming_text: str) -> str:
    """Intelligent lead qualification flow."""
    text_clean = incoming_text.strip().lower()

    if any(greet in text_clean for greet in ["hi", "hello", "hey", "start", "info"]):
        return (
            "Hi there! Welcome to Bloom Craft! 👋\n\n"
            "We help brands and startups scale with high-converting automation & creative services.\n\n"
            "How can we help you today?\n"
            "1. 💼 Explore our services\n"
            "2. 📅 Book a free 15-min discovery call\n"
            "3. 💬 Talk to our team"
        )
    elif any(call_word in text_clean for call_word in ["call", "book", "meeting", "2"]):
        return (
            "Awesome! You can pick a quick 15-min slot that suits your schedule here:\n"
            "👉 https://calendly.com\n\n"
            "What's the best email to send meeting notes to?"
        )
    elif any(price_word in text_clean for price_word in ["price", "pricing", "cost", "service", "services", "1"]):
        return (
            "We build custom automation and creative packages tailored to each client's stage! 🚀\n\n"
            "Could you share a bit about your business or what you're looking to automate?"
        )
    elif any(human_word in text_clean for human_word in ["human", "team", "person", "representative", "3"]):
        return "You got it! I've notified our team. One of our specialists will reply right here in this chat shortly."
    elif "@" in incoming_text:
        return "Thank you! We've received your email address. Our team will review your details and reach out within 24 hours. Have a great day!"
    else:
        return (
            f"Thanks for your message! We received: \"{incoming_text}\".\n\n"
            "Reply '1' to see our services, '2' to book a call, or let us know how we can help!"
        )

@app.get("/")
@app.get("/api")
@app.get("/api/index")
def home(request: Request):
    return {
        "status": "online",
        "service": "Aegis Instagram Lead Bot",
        "version": "1.0.0",
        "token_configured": bool(PAGE_ACCESS_TOKEN),
        "received_path": request.url.path
    }

@app.get("/webhook")
@app.get("/api/webhook")
@app.get("/api/index/webhook")
def meta_webhook_verify(
    request: Request,
    hub_mode: Optional[str] = Query(None, alias="hub.mode"),
    hub_verify_token: Optional[str] = Query(None, alias="hub.verify_token"),
    hub_challenge: Optional[str] = Query(None, alias="hub.challenge"),
):
    """Handles the Meta Webhook handshake."""
    logger.info(f"Handshake request on {request.url.path}: mode={hub_mode}, token={hub_verify_token}")
    if hub_mode == "subscribe" and hub_verify_token == VERIFY_TOKEN:
        logger.info("Verification handshake succeeded!")
        return PlainTextResponse(content=hub_challenge, status_code=200)

    logger.warning("Verification handshake failed.")
    raise HTTPException(status_code=403, detail="Verification token mismatch")

@app.post("/webhook")
@app.post("/api/webhook")
@app.post("/api/index/webhook")
async def meta_webhook_receive(request: Request):
    """Processes incoming messages from Instagram leads."""
    raw_body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256")

    if not verify_meta_signature(raw_body, signature):
        logger.warning("Rejected webhook due to invalid HMAC signature.")
        raise HTTPException(status_code=403, detail="Invalid signature")

    try:
        data = json.loads(raw_body.decode("utf-8"))
    except Exception as e:
        logger.error(f"Malformed JSON: {e}")
        return Response(status_code=200)

    if data.get("object") in ["instagram", "page"]:
        for entry in data.get("entry", []):
            for messaging_event in entry.get("messaging", []):
                # Filter out delivery receipts and bot echoes
                if "message" in messaging_event:
                    msg = messaging_event["message"]
                    if msg.get("is_echo"):
                        continue

                    sender_id = messaging_event.get("sender", {}).get("id")
                    text = msg.get("text", "")

                    if sender_id and text:
                        logger.info(f"Received message from {sender_id}: {text}")
                        reply_text = generate_lead_response(text)
                        # Process inline so Vercel serverless doesn't terminate before reply completes
                        send_instagram_message(sender_id, reply_text)

    return Response(content="EVENT_RECEIVED", status_code=200)
