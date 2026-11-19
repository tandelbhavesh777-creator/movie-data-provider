import json, os, sys, time, hashlib, hmac, base64, urllib.parse, random, re
from datetime import datetime, timezone
from typing import List, Dict, Optional
import requests

# ---- crypto constants from crypto.rs ----
DEFAULT_SECRET_BYTES = b"\xef\xa8\x91\x97\x4e\xec\xd3\x14\x8d\xf6\x3a\xa6\x11\x60\x2d\xef\xd1\x01\x25\x9b\xa5\x21\x02\x2c\x57\xae\x05\x66\xbd\x8e"
SIGNATURE_BODY_MAX_BYTES = 102_400
BUILD_TAG_SALT = "oneroom"
BUILD_TAG_INFO_KEY = "X-Client-Build"
MAX_SEARCH_PAGES = 100
_LAST_NEXT_LINK = None

def build_tag_stamp(ts_ms: int, rand_part: int) -> str:
    return f"{ts_ms // 1000}{ts_ms % 1000:03}000{rand_part}"

def build_tag_for_cert(ts_ms: int, rand_part: int, cert_sha256_hex: str) -> str:
    stamp = build_tag_stamp(ts_ms, rand_part)
    hash_val = hashlib.md5((cert_sha256_hex + BUILD_TAG_SALT + stamp).encode()).hexdigest()
    return f"{stamp}.{hash_val}"

def generate_x_client_build(ts_ms: int) -> str:
    rand_part = random.randint(0, 999)
    return build_tag_for_cert(ts_ms, rand_part, "03d4b741632d136bc23e2de4c6adcdb7712f1980b619c183221801730bbd0410")

def client_info_with_build_tag(client_info: str, tag: str) -> str:
    try:
        obj = json.loads(client_info)
        if isinstance(obj, dict):
            obj[BUILD_TAG_INFO_KEY] = tag
        return json.dumps(obj)
    except Exception:
        return client_info

def insert_header(headers: dict, name: str, value: str, spoof_ip: str = ""):
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
            params.setdefault(k.strip(), []).append(v.strip())
    res = []
    for k in sorted(params):
        for v in params[k]:
            res.append(f"{k}={v}")
    return '&'.join(res)

def build_canonical_string(method, accept, content_type, url, body, timestamp_ms):
    parsed = urllib.parse.urlparse(url)
    query = sorted_query_string(url)
    canonical_url = parsed.path
    if query:
        canonical_url += "?" + query
    body_bytes = body.encode() if body else b''
    body_hash = hashlib.md5(body_bytes[:SIGNATURE_BODY_MAX_BYTES]).hexdigest()
    return f"{method.upper()}\n{accept or ''}\n{content_type or ''}\n{len(body_bytes)}\n{timestamp_ms}\n{body_hash}\n{canonical_url}"

def generate_x_tr_signature(method, accept, content_type, url, body, timestamp_ms):
    canonical = build_canonical_string(method, accept, content_type, url, body, timestamp_ms)
    mac = hmac.new(DEFAULT_SECRET_BYTES, canonical.encode(), hashlib.md5).digest()
    sig_b64 = base64.b64encode(mac).decode()
    return f"{timestamp_ms}|2|{sig_b64}"

def generate_client_info_and_ua():
    android_versions = [
        ("9", "PQ3A.190605.03081104"),
        ("10", "QP1A.191005.007.A3"),
        ("11", "RP1A.200720.011"),
        ("12", "S1B.220414.015"),
        ("13", "TQ2A.230405.003"),
    ]
    redmi_devices = [
        ("23078RKD5C", "Redmi"), ("2201117TY", "Redmi"),
        ("2201117TG", "Redmi"), ("22101316G", "Redmi"),
        ("21121210G", "Redmi"), ("M2012K11AG", "Redmi"),
        ("M2007J20CG", "Redmi"),
    ]
    version_codes = [50020117, 50020118, 50020119, 50020120, 50020121]
    network_types = ["NETWORK_WIFI", "NETWORK_MOBILE"]
    timezones = ["Asia/Kolkata", "Asia/Shanghai", "Asia/Tokyo", "America/New_York", "Europe/London"]

    android = random.choice(android_versions)
    device = random.choice(redmi_devices)
    version_code = random.choice(version_codes)
    network = random.choice(network_types)
    timezone_name = random.choice(timezones)
    gaid = str(__import__("uuid").uuid4())
    device_id = "".join(random.choice("0123456789abcdef") for _ in range(32))

    user_agent = (
        f"com.community.oneroom/{version_code} (Linux; U; Android {android[0]}; en_US; "
        f"{device[0]}; Build/{android[1]}; Cronet/135.0.7012.3)"
    )
    client_info = json.dumps({
        "package_name": "com.community.oneroom",
        "version_name": "4.0.01.0813.03",
        "version_code": version_code,
        "os": "android",
        "os_version": android[0],
        "install_ch": "ps",
        "device_id": device_id,
        "install_store": "ps",
        "gaid": gaid,
        "brand": device[1],
        "model": device[0],
        "system_language": "en",
        "net": network,
        "region": "US",
        "timezone": timezone_name,
        "sp_code": "40401",
        "X-Play-Mode": "2",
    }, separators=(",", ":"))
    return user_agent, client_info

def random_spoofed_ip():
    prefixes = [
        "103.241", "49.36", "117.195", "106.198", "122.162",
        "157.32", "182.70", "103.58", "27.60", "59.90",
    ]
    return f"{random.choice(prefixes)}.{random.randint(1, 253)}.{random.randint(1, 253)}"

def build_signed_headers(method, url, body, auth_token, user_agent, client_info, spoof_ip):
    if not user_agent or not client_info:
        generated_ua, generated_info = generate_client_info_and_ua()
        user_agent = user_agent or generated_ua
        client_info = client_info or generated_info
    spoof_ip = spoof_ip or random_spoofed_ip()
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
    insert_header(headers, "x-forwarded-for", spoof_ip, spoof_ip)
    if auth_token:
        bearer = f"Bearer {auth_token}"
        insert_header(headers, "authorization", bearer)
    return headers

# ---------- HTTP helpers (real requests needed) ----------
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
    body = "{}"
    for base in BASE_HOSTS:
        url = f"{base}{endpoint}"
        try:
            resp = requests.post(
                url,
                data=body,
                headers=build_signed_headers("POST", url, body, None, "", "", ""),
                timeout=12,
            )
            if resp.status_code in RETRY_STATUS_CODES:
                continue
            resp.raise_for_status()
            val = resp.json()
            data = val.get("data") if isinstance(val, dict) else None
            if isinstance(data, dict):
                val = data
            token = val.get("token") if isinstance(val, dict) else None
            uid = (val.get("uid") or val.get("userId")) if isinstance(val, dict) else None
            if isinstance(uid, (int, float)):
                uid = str(uid)
            if isinstance(token, str) and token:
                return token, uid or ""
        except (requests.RequestException, ValueError):
            continue
    raise RuntimeError("Unable to obtain a MovieBox visitor session")

def get_json(path_and_query: str, token: Optional[str] = None) -> Dict:
    if path_and_query.startswith("http://") or path_and_query.startswith("https://"):
        url = path_and_query
    else:
        url = f"{BASE_HOSTS[0]}{path_and_query}"
    resp = requests.get(
        url,
        headers=build_signed_headers("GET", url, None, token, "", "", ""),
        timeout=12,
    )
    resp.raise_for_status()
    val = resp.json()
    return val if isinstance(val, dict) else {}

def _first_subjects(payload: Dict) -> list:
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        data = payload if isinstance(payload, dict) else {}

    results = data.get("results")
    if isinstance(results, list):
        for result in results:
            if isinstance(result, dict) and isinstance(result.get("subjects"), list):
                return result["subjects"]

    subjects = data.get("subjects")
    if isinstance(subjects, list):
        return subjects

    subjects = data.get("list")
    if isinstance(subjects, list):
        return subjects

    if isinstance(payload, dict) and isinstance(payload.get("list"), list):
        return payload["list"]
    return []

def moviebox_subject_json_to_catalog_item(subject: Dict) -> Optional[Dict]:
    subject_id = subject.get("subjectId", subject.get("id"))
    if isinstance(subject_id, (int, float)):
        subject_id = str(subject_id)
    if not isinstance(subject_id, str) or not subject_id:
        return None

    title = subject.get("title", subject.get("name"))
    if not isinstance(title, str) or not title.strip():
        title = "Unknown"

    stype = subject.get("subjectType", subject.get("stype"))
    if not isinstance(stype, int):
        try:
            stype = int(stype)
        except (TypeError, ValueError):
            stype = 1

    release = subject.get("releaseDate") or subject.get("year") or subject.get("releaseInfo")
    year = None
    if isinstance(release, str):
        match = re.search(r"\d{4}", release)
        if match:
            year = match.group(0)

    cover = subject.get("cover")
    poster_url = None
    if isinstance(cover, dict):
        poster_url = cover.get("url")
    if not poster_url:
        poster_url = subject.get("coverUrl") or subject.get("poster") or subject.get("pic")
    if not isinstance(poster_url, str):
        poster_url = None

    season = subject.get("season")
    season_count = season if isinstance(season, int) else None
    resource_link = subject.get("resourceLink")
    url = resource_link if isinstance(resource_link, str) and resource_link else None
    if not url:
        url = f"{BASE_HOSTS[0]}/wefeed-mobile-bff/subject-api/get?subjectId={urllib.parse.quote(subject_id)}"

    item = {
        "id": subject_id,
        "title": title,
        "url": url,
        "media_type": "Series" if stype == 2 else "Movie",
        "poster_url": poster_url,
        "year": year,
        "season_count": season_count,
    }
    if "episode" in subject:
        item["episode"] = subject["episode"]
    return item

def find_next_link(payload: Dict) -> Optional[str]:
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        data = payload if isinstance(payload, dict) else {}

    candidates = [
        data.get("next"),
        payload.get("next"),
        data.get("nextLink"),
        payload.get("nextLink"),
    ]
    pager = data.get("pager") or payload.get("pager")
    if isinstance(pager, dict):
        candidates.extend([
            pager.get("next"),
            pager.get("nextLink"),
            pager.get("nextPage"),
        ])
        if pager.get("hasNext") is True or pager.get("has_next") is True:
            current = pager.get("page") or pager.get("current")
            if isinstance(current, int):
                candidates.append(str(current + 1))
    for candidate in candidates:
        if isinstance(candidate, str) and candidate:
            return candidate
        if isinstance(candidate, dict):
            for key in ("href", "url", "link"):
                value = candidate.get(key)
                if isinstance(value, str) and value:
                    return value
    return None

def moviebox_search_json_to_catalog(payload: Dict) -> List[Dict]:
    items = []
    seen = set()
    for subject in _first_subjects(payload):
        if not isinstance(subject, dict):
            continue
        item = moviebox_subject_json_to_catalog_item(subject)
        if item and item["id"] not in seen:
            seen.add(item["id"])
            items.append(item)
    return items

# ---------- search_page ----------
def search_page(query: str, page: int, seen_urls: set) -> List[Dict]:
    global _LAST_NEXT_LINK
    login_path = "/wefeed-mobile-bff/user-api/visitor-login"
    token, _uid = post_login(login_path)
    search_path = "/wefeed-mobile-bff/subject-api/search/v2"
    body = json.dumps({
        "keyword": query,
        "page": page,
        "perPage": 15,
        "subjectType": 0,
    })
    for base in BASE_HOSTS:
        url = f"{base}{search_path}"
        try:
            resp = requests.post(
                url,
                data=body,
                headers=build_signed_headers("POST", url, body, token, "", "", ""),
                timeout=12,
            )
            if resp.status_code in RETRY_STATUS_CODES:
                continue
            resp.raise_for_status()
            payload = resp.json()
            if not isinstance(payload, dict):
                return []
            _LAST_NEXT_LINK = find_next_link(payload)
            return moviebox_search_json_to_catalog(payload)
        except (requests.RequestException, ValueError):
            continue
    _LAST_NEXT_LINK = None
    return []

# ---------- main ----------
def main():
    movies = []
    seen_urls = set()
    query = "some default query"
    page = 1
    while page <= MAX_SEARCH_PAGES:
        result = search_page(query, page, seen_urls)
        for item in result:
            url = item.get("url")
            if url and url not in seen_urls:
                seen_urls.add(url)
                movies.append({
                    "title": item.get("title"),
                    "url": url,
                })
        if not result:
            break
        next_link = globals().get("_LAST_NEXT_LINK")
        if isinstance(next_link, str):
            if next_link.startswith("http://") or next_link.startswith("https://"):
                # Explicit API next links are handled by their page parameter below.
                parsed = urllib.parse.urlparse(next_link)
                next_page = urllib.parse.parse_qs(parsed.query).get("page")
                if next_page:
                    try:
                        page = int(next_page[0])
                        continue
                    except ValueError:
                        pass
            else:
                try:
                    page = int(next_link)
                    continue
                except ValueError:
                    pass
        if len(result) < 15:
            break
        page += 1
    with open("movies.json", "w") as f:
        json.dump(movies, f, indent=2)

if __name__ == "__main__":
    main()
