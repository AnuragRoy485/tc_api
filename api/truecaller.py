from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote
from urllib.request import Request, build_opener, HTTPCookieProcessor
import http.cookiejar as cookiejar
import json
import os
import pickle
import re

# --------------------------
# CONFIG
# --------------------------
COOKIE_FILE = os.path.join(os.path.dirname(__file__), "truecaller_cookies.pkl")

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


# ---------- Cookie / HTTP helpers ----------

def build_opener_with_cookies():
    """
    Build a urllib opener with cookies loaded from Selenium-exported pickle.
    Cookies are expected as a list of dicts: [{'name': ..., 'value': ..., 'domain': ..., 'path': ...}, ...]
    """
    cj = cookiejar.CookieJar()

    if not os.path.exists(COOKIE_FILE):
        raise FileNotFoundError(f"{COOKIE_FILE} not found on server")

    with open(COOKIE_FILE, "rb") as f:
        cookies_list = pickle.load(f)

    for c in cookies_list:
        name = c.get("name")
        value = c.get("value")
        domain = c.get("domain") or ""
        path = c.get("path") or "/"
        secure = bool(c.get("secure", False))
        expires = c.get("expiry")

        if not name:
            continue

        ck = cookiejar.Cookie(
            version=0,
            name=name,
            value=value,
            port=None,
            port_specified=False,
            domain=domain,
            domain_specified=bool(domain),
            domain_initial_dot=domain.startswith("."),
            path=path,
            path_specified=True,
            secure=secure,
            expires=expires,
            discard=False,
            comment=None,
            comment_url=None,
            rest={},
            rfc2109=False,
        )
        cj.set_cookie(ck)

    opener = build_opener(HTTPCookieProcessor(cj))
    return opener


def http_get(url, timeout=15):
    opener = build_opener_with_cookies()
    req = Request(
        url,
        headers={
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://www.truecaller.com/",
        },
    )
    resp = opener.open(req, timeout=timeout)
    body = resp.read().decode("utf-8", errors="ignore")
    status = resp.getcode()
    return status, body


# ---------- Parsing helpers (no BeautifulSoup) ----------

def strip_tags(html: str) -> str:
    """Remove HTML tags to get a plain-text dump."""
    text = re.sub(r"<script.*?</script>", " ", html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<style.*?</style>", " ", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def parse_full_profile(html_content: str, phone_input: str):
    data = {
        "phone": phone_input,
        "name": None,
        "alt_name": None,
        "email": None,
        "location": "Unknown",
        "carrier": "Unknown",
        "image_url": None,
        "type": "Person",
        "spam_score": None,
        "status": "Success",
    }

    text_dump = strip_tags(html_content)
    lower_text = text_dump.lower()

    # --- 1. vCard extraction ---
    try:
        vcard_match = re.search(
            r'href="(data:text/vcard;charset=utf-8,[^"]+)"',
            html_content,
            flags=re.IGNORECASE,
        )
        if vcard_match:
            raw_vcard = unquote(vcard_match.group(1))

            fn_match = re.search(r"\nFN:(.+)", raw_vcard)
            if fn_match:
                data["name"] = fn_match.group(1).strip()

            email_match = re.search(r"\nEMAIL:(.+)", raw_vcard)
            if email_match:
                data["email"] = email_match.group(1).strip()

            adr_match = re.search(r"\nADR.*?:(.*)", raw_vcard)
            if adr_match:
                raw_loc = adr_match.group(1).replace(";", " ").strip()
                if raw_loc:
                    data["location"] = raw_loc
    except Exception as e:
        data["vcard_error"] = str(e)

    # --- 2. Profile image ---
    img_matches = re.findall(
        r'<img[^>]+src=["\']([^"\']+)["\']',
        html_content,
        flags=re.IGNORECASE,
    )
    for src in img_matches:
        if any(k in src for k in ("myview", "googleusercontent", "facebook")) and "user.svg" not in src:
            data["image_url"] = src
            break

    # --- 3. Name fallback (font-bold) ---
    if not data["name"]:
        m = re.search(
            r"<(div|span)[^>]*class=[\"'][^\"']*font-bold[^\"']*[\"'][^>]*>(.*?)</\1>",
            html_content,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if m:
            # Strip inner tags
            inner = re.sub(r"<[^>]+>", " ", m.group(2))
            inner = re.sub(r"\s+", " ", inner).strip()
            if inner and "truecaller" not in inner.lower():
                data["name"] = inner

    # --- 4. Alt name (opacity-75) ---
    m_alt = re.search(
        r"<div[^>]*class=[\"'][^\"']*opacity-75[^\"']*[\"'][^>]*>(.*?)</div>",
        html_content,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if m_alt:
        inner = re.sub(r"<[^>]+>", " ", m_alt.group(1))
        inner = re.sub(r"\s+", " ", inner).strip()
        if "(" in inner and ")" in inner:
            data["alt_name"] = inner

    # --- 5. Type / spam ---
    if "likely a business" in lower_text:
        data["type"] = "Likely a Business"
    elif "spam" in lower_text:
        count = re.search(r"(\d+)\s*spam", lower_text)
        if count:
            data["spam_score"] = f"Reported {count.group(1)} times"
        else:
            data["spam_score"] = "Yes, Reported as Spam"

    # --- 6. Carrier detection ---
    if data["carrier"] == "Unknown":
        carriers = ["Airtel", "Jio", "Vi", "Vodafone", "Idea", "BSNL", "MTNL"]
        for c in carriers:
            if c.lower() in lower_text:
                data["carrier"] = c
                break

    return data


# ---------- Core lookup ----------

def lookup_number(raw_phone: str):
    phone_num = re.sub(r"[^\d]", "", raw_phone or "")

    if not phone_num:
        return {"status": "Error", "error": "Phone number is required"}

    # If 10 digits, assume Indian mobile and prepend 91
    if not phone_num.startswith("91") and len(phone_num) == 10:
        phone_num = "91" + phone_num

    url = f"https://www.truecaller.com/search/in/{phone_num}"

    try:
        status_code, html = http_get(url)
    except FileNotFoundError as e:
        return {
            "status": "Error",
            "error": "Cookie file missing on server. Upload truecaller_cookies.pkl beside this file.",
            "details": str(e),
        }
    except Exception as e:
        return {
            "status": "Error",
            "error": "Request to Truecaller failed",
            "details": str(e),
        }

    if status_code == 200:
        lower_html = html.lower()
        if "sign in" in lower_html and "unlock" in lower_html:
            return {
                "status": "Error",
                "error": "Login expired or IP blocked by Truecaller",
            }
        return parse_full_profile(html, phone_num)

    if status_code == 404:
        return {
            "status": "NotFound",
            "error": "Number not found in Truecaller database",
            "phone": phone_num,
        }

    if status_code == 403:
        return {
            "status": "Forbidden",
            "error": "403 Blocked (WAF or IP blocked)",
            "phone": phone_num,
        }

    return {
        "status": "Error",
        "error": f"Unexpected HTTP status code: {status_code}",
        "phone": phone_num,
    }


# ---------- Vercel handler ----------

class handler(BaseHTTPRequestHandler):
    """
    Endpoint examples:
      GET /api/truecaller?phone=9199XXXXXXXX
      GET /api/truecaller?mobile=99XXXXXXXXXX
    """

    def _send_json(self, status_code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)

        phone = qs.get("phone", [None])[0] or qs.get("mobile", [None])[0]

        if not phone:
            self._send_json(
                400,
                {
                    "status": "Error",
                    "error": "Query param 'phone' or 'mobile' is required, e.g. /api/truecaller?phone=9199XXXXXXXX",
                },
            )
            return

        result = lookup_number(phone)

        status = result.get("status")
        if status == "Success":
            self._send_json(200, result)
        elif status == "NotFound":
            self._send_json(404, result)
        elif status == "Forbidden":
            self._send_json(403, result)
        else:
            self._send_json(500, result)
