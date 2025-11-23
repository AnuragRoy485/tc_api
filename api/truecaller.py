from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote
import json
import os
import pickle
import re
import requests
from bs4 import BeautifulSoup

# --------------------------
# CONFIG
# --------------------------
COOKIE_FILE = os.path.join(os.path.dirname(__file__), "truecaller_cookies.pkl")

def load_cookies_into_session(session):
    """
    Load Selenium-exported cookies (pickled list of dicts) into a requests session.
    """
    if not os.path.exists(COOKIE_FILE):
        raise FileNotFoundError(f"{COOKIE_FILE} not found on server")

    with open(COOKIE_FILE, 'rb') as f:
        cookies_list = pickle.load(f)

    for cookie in cookies_list:
        session.cookies.set(
            cookie.get("name"),
            cookie.get("value"),
            domain=cookie.get("domain")
        )


def parse_full_profile(html_content, phone_input):
    """
    Parses: Name, Image, Email (vCard), Location, Spam Score, & Business Tags
    (adapted from your original script)
    """
    soup = BeautifulSoup(html_content, 'html.parser')

    data = {
        "phone": phone_input,
        "name": None,
        "alt_name": None,        # Bracket wala naam eg: ( Tdp )
        "email": None,           # vCard se
        "location": "Unknown",
        "carrier": "Unknown",
        "image_url": None,       # Profile Pic
        "type": "Person",        # Business / Spam / Person
        "spam_score": None,
        "status": "Success"
    }

    text_dump = soup.get_text(" ", strip=True)

    # 1. vCARD extraction
    try:
        vcard_match = re.search(r'href="(data:text/vcard;charset=utf-8,[^"]+)"', html_content)
        if vcard_match:
            raw_vcard = unquote(vcard_match.group(1))

            fn_match = re.search(r'FN:(.+)', raw_vcard)
            if fn_match:
                data["name"] = fn_match.group(1).strip()

            email_match = re.search(r'EMAIL:(.+)', raw_vcard)
            if email_match:
                data["email"] = email_match.group(1).strip()

            adr_match = re.search(r'ADR.*?:(.*)', raw_vcard)
            if adr_match:
                raw_loc = adr_match.group(1).replace(';', ' ').strip()
                if raw_loc:
                    data["location"] = raw_loc

            # ORG check is usually for business, but HTML double-check is better
    except Exception as e:
        # Don’t crash; just continue with other methods
        data["vcard_error"] = str(e)

    # 2. HTML visual parsing

    # A. Profile Image
    img_tags = soup.find_all('img')
    for img in img_tags:
        src = img.get('src', '')
        if "myview" in src or "googleusercontent" in src or "facebook" in src:
            if "user.svg" not in src:  # Skip default icon
                data["image_url"] = src
                break

    # B. Name fallback
    if not data["name"]:
        bold_divs = soup.find_all(['div', 'span'], class_=lambda x: x and 'font-bold' in x)
        for b in bold_divs:
            txt = b.get_text(strip=True)
            if len(txt) > 2 and "Truecaller" not in txt and "Search" not in txt:
                data["name"] = txt
                break

    # Alt name in brackets
    opacity_divs = soup.find_all('div', class_=lambda x: x and 'opacity-75' in x)
    for op in opacity_divs:
        txt = op.get_text(strip=True)
        if "(" in txt and ")" in txt:
            data["alt_name"] = txt

    # C. Spam / Business
    if "Likely a business" in text_dump:
        data["type"] = "Likely a Business"
    elif "spam" in text_dump.lower():
        count = re.search(r'(\d+)\s*spam', text_dump.lower())
        if count:
            data["spam_score"] = f"Reported {count.group(1)} times"
        else:
            data["spam_score"] = "Yes, Reported as Spam"

    # D. Carrier
    if data["carrier"] == "Unknown":
        carriers = ['Airtel', 'Jio', 'Vi', 'Vodafone', 'Idea', 'BSNL', 'MTNL']
        for c in carriers:
            if c in text_dump:
                data["carrier"] = c
                break

    return data


def lookup_number(raw_phone: str):
    """
    Core lookup function: takes raw phone string, cleans + normalizes, queries Truecaller,
    returns structured JSON dict or error.
    """
    # clean to digits
    phone_num = re.sub(r'[^\d]', '', raw_phone or "")

    if not phone_num:
        return {
            "status": "Error",
            "error": "Phone number is required"
        }

    # If only 10 digits, assume Indian number and prepend 91
    if not phone_num.startswith("91") and len(phone_num) == 10:
        phone_num = "91" + phone_num

    target_url = f"https://www.truecaller.com/search/in/{phone_num}"

    session = requests.Session()
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://www.truecaller.com/",
    })

    try:
        load_cookies_into_session(session)
    except FileNotFoundError as e:
        return {
            "status": "Error",
            "error": "Cookie file missing on server. Upload truecaller_cookies.pkl beside this file.",
            "details": str(e)
        }
    except Exception as e:
        return {
            "status": "Error",
            "error": "Failed to load cookies into session",
            "details": str(e)
        }

    try:
        response = session.get(target_url, timeout=15)
    except Exception as e:
        return {
            "status": "Error",
            "error": "Request to Truecaller failed",
            "details": str(e)
        }

    if response.status_code == 200:
        text_lower = response.text.lower()
        if "sign in" in text_lower and "unlock" in text_lower:
            return {
                "status": "Error",
                "error": "Login expired or IP blocked by Truecaller"
            }

        result = parse_full_profile(response.text, phone_num)
        return result

    elif response.status_code == 404:
        return {
            "status": "NotFound",
            "error": "Number not found in Truecaller database",
            "phone": phone_num
        }
    elif response.status_code == 403:
        return {
            "status": "Forbidden",
            "error": "403 Blocked (WAF or IP blocked)",
            "phone": phone_num
        }
    else:
        return {
            "status": "Error",
            "error": f"Unexpected HTTP status code: {response.status_code}",
            "phone": phone_num
        }


class handler(BaseHTTPRequestHandler):
    """
    Vercel Python Serverless Function handler.
    Endpoint example:
      GET /api/truecaller?phone=9199XXXXXXXX
      GET /api/truecaller?mobile=99XXXXXXXXXX
    """

    def _send_json(self, status_code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # CORS (optional, but useful if you call from frontend)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        # Handle CORS preflight if needed
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)

        # Accept both ?phone= and ?mobile=
        phone = (
            qs.get("phone", [None])[0]
            or qs.get("mobile", [None])[0]
        )

        if not phone:
            self._send_json(400, {
                "status": "Error",
                "error": "Query param 'phone' or 'mobile' is required, e.g. /api/truecaller?phone=9199XXXXXXXX"
            })
            return

        result = lookup_number(phone)

        # Decide HTTP status based on result
        if result.get("status") == "Success":
            self._send_json(200, result)
        elif result.get("status") == "NotFound":
            self._send_json(404, result)
        elif result.get("status") == "Forbidden":
            self._send_json(403, result)
        else:
            # Generic error
            self._send_json(500, result)
