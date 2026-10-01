import os
import re
import hmac
import hashlib
import json
import logging
import asyncio
import time
from collections import OrderedDict
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

REQUIRE_SIGNATURE = os.getenv("REQUIRE_WEBHOOK_SIGNATURE", "true").lower() in ("1", "true", "yes")

if not APP_SECRET:
    logger.warning(
        "META_APP_SECRET is not set. Webhook signature verification is disabled, "
        "so anyone who knows the URL can trigger replies."
    )

DEDUPE_TTL_SECONDS = int(os.getenv("WEBHOOK_DEDUPE_TTL", "900"))
DEDUPE_MAX_ENTRIES = int(os.getenv("WEBHOOK_DEDUPE_MAX", "2000"))

# Meta retries a webhook until it gets a 2xx, and retries are not tagged with the
# original delivery id. Keyed on the message mid so a retry never double-replies.
_seen_messages: "OrderedDict[str, float]" = OrderedDict()


def claim_message(message_id: Optional[str]) -> bool:
    """Returns True if this message id has not been processed before."""
    if not message_id:
        return True

    now = time.time()
    cutoff = now - DEDUPE_TTL_SECONDS

    for key in [k for k, ts in _seen_messages.items() if ts < cutoff]:
        _seen_messages.pop(key, None)

    if message_id in _seen_messages:
        return False

    _seen_messages[message_id] = now
    while len(_seen_messages) > DEDUPE_MAX_ENTRIES:
        _seen_messages.popitem(last=False)
    return True


def verify_meta_signature(payload: bytes, signature_header: Optional[str]) -> bool:
    """Verifies HMAC SHA-256 signature from Meta to prevent spoofing."""
    if not APP_SECRET:
        return not REQUIRE_SIGNATURE
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected_hash = signature_header.split("=", 1)[1]
    calculated_hash = hmac.new(
        APP_SECRET.encode("utf-8"),
        payload,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(calculated_hash, expected_hash)

def _send_instagram_message_sync(recipient_id: str, text: str):
    """Blocking Graph API call. Runs in a worker thread, never on the event loop."""
    if not PAGE_ACCESS_TOKEN:
        logger.warning(f"No access token configured. Skipping reply to {recipient_id}")
        return

    url = f"https://graph.instagram.com/{GRAPH_API_VERSION}/me/messages"
    payload = {
        "recipient": {"id": recipient_id},
        "message": {"text": text}
    }
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {PAGE_ACCESS_TOKEN}"
    }

    try:
        res = requests.post(url, json=payload, headers=headers, timeout=10)
        if res.status_code == 200:
            logger.info(f"Sent reply to {recipient_id}: message_id={res.json().get('message_id')}")
            return
        logger.warning(f"Graph API rejected reply to {recipient_id} (HTTP {res.status_code}): {res.text[:400]}")
    except Exception as e:
        logger.error(f"Error sending message to {recipient_id}: {e}")


async def send_instagram_message(recipient_id: str, text: str):
    """Sends reply via Instagram Graph API without blocking the event loop."""
    await asyncio.to_thread(_send_instagram_message_sync, recipient_id, text)

GREETING_RE = re.compile(r"\b(?:hi|hello|hey|start|info)\b", re.IGNORECASE)
BOOKING_RE = re.compile(r"\b(?:call|book|booking|meeting|schedule|demo|2)\b", re.IGNORECASE)
SERVICES_RE = re.compile(r"\b(?:service|services|pricing|price|cost|budget|quote|package|1)\b", re.IGNORECASE)
HUMAN_RE = re.compile(r"\b(?:human|team|person|representative|rep|sales|3)\b", re.IGNORECASE)
EMAIL_RE = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+")


def generate_lead_response(incoming_text: str) -> str:
    """Intent routing for the lead qualification flow.

    Patterns use word boundaries. Substring matching sent "this", "which", "31" and
    "option 12" down the wrong branches, so leads got the wrong menu.
    """
    text = incoming_text.strip()

    if EMAIL_RE.search(text):
        return (
            "Thank you! We've received your email address. Our team will review your "
            "details and reach out within 24 hours. Have a great day!"
        )
    elif HUMAN_RE.search(text):
        return "You got it! I've notified our team. One of our specialists will reply right here in this chat shortly."
    elif BOOKING_RE.search(text):
        return (
            "Awesome! You can pick a quick 15-min slot that suits your schedule here:\n"
            "👉 https://calendly.com\n\n"
            "What's the best email to send meeting notes to?"
        )
    elif SERVICES_RE.search(text):
        return (
            "We build custom automation and creative packages tailored to each client's stage! 🚀\n\n"
            "Could you share a bit about your business or what you're looking to automate?"
        )
    elif GREETING_RE.search(text):
        return (
            "Hi there! Welcome to Bloom Craft! 👋\n\n"
            "We help brands and startups scale with high-converting automation & creative services.\n\n"
            "How can we help you today?\n"
            "1. 💼 Explore our services\n"
            "2. 📅 Book a free 15-min discovery call\n"
            "3. 💬 Talk to our team"
        )
    else:
        return (
            f"Thanks for your message! We received: \"{text}\".\n\n"
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
@app.get("/instagram-webhook")
@app.get("/api/instagram-webhook")
@app.get("/api/index/instagram-webhook")
def meta_webhook_verify(
    request: Request,
    hub_mode: Optional[str] = Query(None, alias="hub.mode"),
    hub_verify_token: Optional[str] = Query(None, alias="hub.verify_token"),
    hub_challenge: Optional[str] = Query(None, alias="hub.challenge"),
):
    """Handles the Meta Webhook handshake."""
    logger.info(f"Handshake request on {request.url.path}: mode={hub_mode}, token_match={hub_verify_token == VERIFY_TOKEN}")
    if hub_mode == "subscribe" and hub_verify_token == VERIFY_TOKEN and hub_challenge is not None:
        logger.info("Verification handshake succeeded!")
        return PlainTextResponse(content=hub_challenge, status_code=200)

    logger.warning("Verification handshake failed.")
    raise HTTPException(status_code=403, detail="Verification token mismatch")

@app.post("/webhook")
@app.post("/api/webhook")
@app.post("/api/index/webhook")
@app.post("/instagram-webhook")
@app.post("/api/instagram-webhook")
@app.post("/api/index/instagram-webhook")
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
                    message_id = msg.get("mid")

                    if not (sender_id and text):
                        continue

                    if not claim_message(message_id):
                        logger.info(f"Skipped duplicate delivery of {message_id} from {sender_id}")
                        continue

                    logger.info(f"Received message from {sender_id}: {text}")
                    reply_text = generate_lead_response(text)
                    # Awaited inline: the Vercel serverless runtime freezes the instance
                    # as soon as the response is returned, so the reply must complete first.
                    await send_instagram_message(sender_id, reply_text)

    return Response(content="EVENT_RECEIVED", status_code=200)
