import json, os, sys, time, hashlib, hmac, base64, urllib.parse, random
from datetime import datetime, timezone
from typing import List, Dict, Optional

# ---- crypto constants from crypto.rs ----
DEFAULT_SECRET_BYTES = b"\xef\xa8\x91\x97\x4e\xec\xd3\x14\x8d\xf6\x3a\xa6\x11\x60\x2d\xef\xd1\x01\x25\x9b\xa5\x21\x02\x2c\x57\xae\x05\x66\xbd\x8e"
SIGNATURE_BODY_MAX_BYTES = 102_400
BUILD_TAG_SALT = "oneroom"

def build_tag_stamp(ts_ms: int, rand_part: int) -> str:
    return f"{ts_ms // 1000:03}{ts_ms % 1000:03}{rand_part}"

def build_tag_for_cert(ts_ms: int, rand_part: int, cert_sha256_hex: str) -> str:
    stamp = build_tag_stamp(ts_ms, rand_part)
    hash_val = hashlib.md5((cert_sha256_hex + BUILD_TAG_SALT + stamp).encode()).hexdigest()
    return f"{stamp}.{hash_val}"

def generate_x_client_build(ts_ms: int) -> str:
    rng = random.Random()
    rand_part = rng.randint(0, 1000)
    return build_tag_for_cert(ts_ms, rand_part, DEFAULT_SECRET_BYTES.decode())

def client_info_with_build_tag(client_info: str, tag: str) -> str:
    try:
        obj = json.loads(client_info)
        if isinstance(obj, dict):
            obj[BUILD_TAG_INFO_KEY] = tag
        return json.dumps(obj)
    except Exception:
        return client_info

def insert_header(headers: dict, name: str, value: str):
    header_map = {}
    if name == "user-agent":
        header_map["User-Agent"] = value
    elif name == "accept":
        header_map["Accept"] = value
    elif name == "content-type":
        header_map["Content-Type"] = value
    elif name == "connection":
        header_map["Connection"] = "keep-alive"
    elif name == "x-client-token":
        header_map["X-Client-Token"] = value
    elif name == "x-tr-signature":
        header_map["X-Client-Tr-Signature"] = value
    elif name == "x-client-build":
        header_map["X-Client-Build"] = value
    elif name == "x-client-info":
        header_map["X-Client-Info"] = value
    elif name == "x-client-status":
        header_map["X-Client-Status"] = "0"
    elif name == "x-forwarded-for":
        header_map["X-Forwarded-For"] = spoof_ip
    else:
        pass
    for k, v in header_map.items():
        headers[k] = v

def generate_x_client_token(ts_ms: int) -> str:
    ts_str = str(ts_ms)
    reversed_ts = ''.join(reversed(ts_str))
    md5_bytes = hashlib.md5(reversed_ts.encode()).hexdigest()
    return f"{ts_str},{md5_bytes}"

def sorted_query_string(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    params = {}
    for p in parsed.query.split('&'):
        if '=' in p:
            k, v = p.split('=', 1)
            params[k.strip()] = v.strip()
    res = []
    for k, v in params.items():
        res.append(f"{k}={v}")
    return '&'.join(res)

def build_canonical_string(method, accept, content_type, url, body, timestamp_ms):
    canonical_url = url
    body_bytes = body.encode() if body else b''
    body_hash = hashlib.md5(body_bytes[:SIGNATURE_BODY_MAX_BYTES]).hexdigest()
    return f"{method.upper()}\n{accept or ''}\n{content_type or ''}\n{len(body_bytes)}\n{timestamp_ms}\n{body_hash}\n{canonical_url}"

def generate_x_tr_signature(method, accept, content_type, url, body, timestamp_ms):
    canonical = build_canonical_string(method, accept, content_type, url, body, timestamp_ms)
    mac = hmac.new(DEFAULT_SECRET_BYTES, canonical.encode(), hashlib.md5).digest()
    sig_b64 = base64.b64encode(mac).decode()
    return f"{timestamp_ms}|2|{sig_b64}"

def build_signed_headers(method, url, body, auth_token, user_agent, client_info, spoof_ip):
    ts = int(datetime.now(timezone.utc).timestamp() * 1000)
    build_tag = generate_x_client_build(ts)
    client_info_full = client_info_with_build_tag(client_info, build_tag)
    client_token = generate_x_client_token(ts)
    signature = generate_x_tr_signature(method, "application/json", "application/json", url, body, ts)
    headers = {}
    insert_header(headers, "user-agent", user_agent)
    insert_header(headers, "accept", "application/json")
    insert_header(headers, "content-type", "application/json")
    insert_header(headers, "connection", "keep-alive")
    insert_header(headers, "x-client-token", client_token)
    insert_header(headers, "x-tr-signature", signature)
    insert_header(headers, "x-client-build", build_tag)
    insert_header(headers, "x-client-info", client_info_full)
    insert_header(headers, "x-client-status", "0")
    insert_header(headers, "x-forwarded-for", spoof_ip)
    if auth_token:
        bearer = f"Bearer {auth_token}"
        insert_header(headers, "authorization", bearer)
    return headers

# ---------- REAL HTTP helpers (replace with actual requests) ----------
BASE_HOSTS = [
    "https://api6.aoneroom.com",
    "https://api5.aoneroom.com",
    "https://api4.aoneroom.com",
    "https://api4sg.aoneroom.com",
    "https://api3.aoneroom.com",
    "https://api6sg.aoneroom.com",
    "https://api.inmoviebox.com",
]

RETRY_STATUS_CODES = [403, 406, 407, 429, 500, 502, 503, 504]
STREAM_REFERER = "https://sportslive.wine"

def post_login(endpoint: str) -> tuple[str, str]:
    """
    POST /wefeed-mobile-bff/user-api/visitor-login
    Returns (token, uid)
    """
    resp = requests.post(f"{BASE_HOSTS[0]}/user-api/visitor-login", json={}, headers=build_signed_headers("POST", endpoint, None, None, "", "", ""))
    val = resp.json()
    token = val.get("token
