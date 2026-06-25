from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from html.parser import HTMLParser
from http.cookiejar import CookieJar
from pathlib import Path


DEFAULT_URL = "http://172.19.1.1/"
SUCCESS_WORDS = ("success", "ok", "online", "logout")
FAIL_WORDS = ("fail", "failed", "error", "invalid")
CN_SUCCESS_WORDS = ("成功", "已登录", "认证成功", "在线", "注销")
CN_FAIL_WORDS = ("错误", "失败", "密码错误", "认证失败")
RAAS_KEY = b"5a3b9f207411a8ed"
RAAS_RANDOM_MAP = "abacdefghjklmnopqrstuvwxyzABCDEFGHJKLMNOPQRSTUVWXYZ0123456789"


SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def _gmul(left: int, right: int) -> int:
    result = 0
    for _ in range(8):
        if right & 1:
            result ^= left
        high = left & 0x80
        left = (left << 1) & 0xFF
        if high:
            left ^= 0x1B
        right >>= 1
    return result


def _expand_aes128_key(key: bytes) -> list[list[int]]:
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")
    words = [list(key[index : index + 4]) for index in range(0, 16, 4)]
    for index in range(4, 44):
        temp = words[index - 1].copy()
        if index % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[item] for item in temp]
            temp[0] ^= RCON[index // 4 - 1]
        words.append([words[index - 4][pos] ^ temp[pos] for pos in range(4)])
    return [sum(words[index : index + 4], []) for index in range(0, 44, 4)]


def _add_round_key(state: list[int], round_key: list[int]) -> None:
    for index in range(16):
        state[index] ^= round_key[index]


def _sub_bytes(state: list[int]) -> None:
    for index, value in enumerate(state):
        state[index] = SBOX[value]


def _shift_rows(state: list[int]) -> None:
    state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]


def _mix_columns(state: list[int]) -> None:
    for col in range(4):
        offset = col * 4
        a0, a1, a2, a3 = state[offset : offset + 4]
        state[offset] = _gmul(a0, 2) ^ _gmul(a1, 3) ^ a2 ^ a3
        state[offset + 1] = a0 ^ _gmul(a1, 2) ^ _gmul(a2, 3) ^ a3
        state[offset + 2] = a0 ^ a1 ^ _gmul(a2, 2) ^ _gmul(a3, 3)
        state[offset + 3] = _gmul(a0, 3) ^ a1 ^ a2 ^ _gmul(a3, 2)


def aes128_ecb_encrypt_zero_padded(data: bytes, key: bytes) -> bytes:
    pad_len = (16 - len(data) % 16) % 16
    data += b"\x00" * pad_len
    round_keys = _expand_aes128_key(key)
    output = bytearray()
    for block_start in range(0, len(data), 16):
        state = list(data[block_start : block_start + 16])
        _add_round_key(state, round_keys[0])
        for round_index in range(1, 10):
            _sub_bytes(state)
            _shift_rows(state)
            _mix_columns(state)
            _add_round_key(state, round_keys[round_index])
        _sub_bytes(state)
        _shift_rows(state)
        _add_round_key(state, round_keys[10])
        output.extend(state)
    return bytes(output)


def encode_raas_password(password: str) -> str:
    if re.fullmatch(r"[0-9A-Za-z]{32}", password):
        return password
    if len(password) >= 24:
        raise RuntimeError("RAAS portal password is too long; it must be shorter than 24 characters.")
    prefix = "".join(secrets.choice(RAAS_RANDOM_MAP) for _ in range(4))
    return aes128_ecb_encrypt_zero_padded((prefix + password).encode("utf-8"), RAAS_KEY).hex()


@dataclass
class Field:
    tag: str
    attrs: dict[str, str]

    @property
    def key(self) -> str:
        return self.attrs.get("name") or self.attrs.get("id") or ""

    @property
    def name(self) -> str:
        return self.attrs.get("name", "")

    @property
    def value(self) -> str:
        return self.attrs.get("value", "")

    @property
    def type(self) -> str:
        raw_type = self.attrs.get("type", "text").lower()
        if self.tag == "select":
            return "select"
        return raw_type

    def describe(self) -> str:
        bits = [self.tag]
        for attr in ("name", "id", "type", "placeholder", "value"):
            value = self.attrs.get(attr)
            if value:
                bits.append(f"{attr}={value!r}")
        return " ".join(bits)


@dataclass
class Form:
    attrs: dict[str, str]
    fields: list[Field] = field(default_factory=list)

    @property
    def method(self) -> str:
        return self.attrs.get("method", "get").lower()

    @property
    def action(self) -> str:
        return self.attrs.get("action", "")

    @property
    def synthetic(self) -> bool:
        return self.attrs.get("data-synthetic") == "1"


class LoginPageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[Form] = []
        self.all_fields: list[Field] = []
        self.scripts: list[str] = []
        self._current: Form | None = None

    def handle_starttag(self, tag: str, attrs_list: list[tuple[str, str | None]]) -> None:
        attrs = {key.lower(): value or "" for key, value in attrs_list}
        if tag == "script" and attrs.get("src"):
            self.scripts.append(attrs["src"])
            return
        if tag == "form":
            self._current = Form(attrs=attrs)
            self.forms.append(self._current)
            return

        if tag not in {"input", "button", "textarea", "select"}:
            return

        field_obj = Field(tag=tag, attrs=attrs)
        self.all_fields.append(field_obj)
        if self._current is not None:
            self._current.fields.append(field_obj)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current = None


def field_score(field_obj: Field, words: tuple[str, ...]) -> int:
    haystack = " ".join(
        field_obj.attrs.get(key, "")
        for key in ("name", "id", "placeholder", "class", "autocomplete")
    ).lower()
    score = 0
    for word in words:
        if word in haystack:
            score += 3
    if field_obj.type == "password" and "pass" in words:
        score += 10
    return score


def usable_key(field_obj: Field) -> str:
    return field_obj.key


def find_field(form: Form, configured: str, kind: str) -> str | None:
    if configured:
        return configured

    if kind == "password":
        words = ("password", "passwd", "pass", "pwd", "upass", "userpass")
        allowed = {"password", "text"}
    elif kind == "username":
        words = (
            "username",
            "user",
            "account",
            "login",
            "userid",
            "uid",
            "phone",
            "student",
            "xh",
            "ddddd",
        )
        allowed = {"text", "tel", "email", "number", "hidden"}
    else:
        words = ("operator", "isp", "service", "domain", "provider", "nasip")
        allowed = {"text", "hidden", "select"}

    candidates = [
        field_obj
        for field_obj in form.fields
        if usable_key(field_obj)
        and field_obj.type in allowed
        and field_obj.type not in {"submit", "button", "image", "reset"}
    ]

    if kind == "password":
        for field_obj in candidates:
            if field_obj.type == "password":
                return usable_key(field_obj)

    ranked = sorted(candidates, key=lambda item: field_score(item, words), reverse=True)
    if ranked and field_score(ranked[0], words) > 0:
        return usable_key(ranked[0])
    if kind == "username":
        for field_obj in candidates:
            if field_obj.type != "hidden":
                return usable_key(field_obj)
    return None


def choose_form(forms: list[Form], all_fields: list[Field]) -> Form:
    with_password = [form for form in forms if any(item.type == "password" for item in form.fields)]
    if with_password:
        return with_password[0]
    if forms:
        return forms[0]
    if all_fields:
        return Form(attrs={"method": "post", "data-synthetic": "1"}, fields=all_fields)
    raise RuntimeError(
        "No form or input fields found in the initial HTML. "
        "This is probably a fully JavaScript-rendered portal. "
        "Run with --scan-assets to print possible login API hints, or inspect "
        "Network during login and set CAMPUS_SUBMIT_URL, CAMPUS_USERNAME_FIELD "
        "and CAMPUS_PASSWORD_FIELD in .env."
    )


def build_payload(
    form: Form,
    require_credentials: bool = True,
    password_encoding: str = "",
) -> dict[str, str]:
    username = os.getenv("CAMPUS_USERNAME", "")
    password = os.getenv("CAMPUS_PASSWORD", "")
    if require_credentials and (not username or not password):
        raise RuntimeError("Please fill CAMPUS_USERNAME and CAMPUS_PASSWORD in .env.")
    username = username or "<username>"
    password = password or "<password>"

    payload: dict[str, str] = {}
    for field_obj in form.fields:
        if password_encoding == "raas-aes" and not field_obj.name:
            continue
        key = usable_key(field_obj)
        if not key or field_obj.type in {"submit", "button", "image", "reset"}:
            continue
        payload[key] = field_obj.value

    user_field = find_field(form, os.getenv("CAMPUS_USERNAME_FIELD", ""), "username")
    pass_field = find_field(form, os.getenv("CAMPUS_PASSWORD_FIELD", ""), "password")
    if not user_field or not pass_field:
        names = ", ".join(field_obj.describe() for field_obj in form.fields)
        raise RuntimeError(
            "Could not detect username/password fields. "
            f"Fields found: {names or '(none)'}. "
            "Set CAMPUS_USERNAME_FIELD and CAMPUS_PASSWORD_FIELD in .env."
        )

    if password_encoding == "raas-aes" and password != "<password>":
        password = encode_raas_password(password)

    payload[user_field] = username
    payload[pass_field] = password

    operator = os.getenv("CAMPUS_OPERATOR", "")
    if operator:
        operator_field = find_field(form, os.getenv("CAMPUS_OPERATOR_FIELD", ""), "operator")
        if operator_field:
            payload[operator_field] = operator

    extra = os.getenv("CAMPUS_EXTRA_FIELDS", "").strip()
    if extra:
        payload.update(json.loads(extra))

    return payload


def detect_candidate_urls(html: str, final_url: str) -> list[str]:
    found: list[str] = []
    patterns = [
        r"""(?:url|action)\s*[:=]\s*['"]([^'"]+(?:login|auth|portal|inter|interface)[^'"]*)['"]""",
        r"""['"]([^'"]+(?:login|auth|portal|InterFace|interface)[^'"]*)['"]""",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, html, flags=re.IGNORECASE):
            candidate = urllib.parse.urljoin(final_url, match.group(1))
            if candidate not in found:
                found.append(candidate)
    return found[:8]


def detect_raas_tp(html: str) -> str:
    match = re.search(r'"tp"\s*:\s*"([^"]+)"', html)
    return match.group(1) if match else ""


def detect_candidate_fields(source: str) -> list[str]:
    words = (
        "username",
        "password",
        "account",
        "user",
        "passwd",
        "pwd",
        "DDDDD",
        "upass",
        "token",
        "mac",
        "ip",
        "vlan",
    )
    found: list[str] = []
    for word in words:
        if re.search(rf"\b{re.escape(word)}\b", source, flags=re.IGNORECASE) and word not in found:
            found.append(word)
    for match in re.finditer(r"""['"]([A-Za-z_][A-Za-z0-9_@.-]{2,30})['"]\s*:""", source):
        key = match.group(1)
        if key.lower() in {"success", "message", "data", "route", "config"}:
            continue
        if key not in found:
            found.append(key)
    return found[:30]


def scan_script_assets(
    opener: urllib.request.OpenerDirector,
    final_url: str,
    scripts: list[str],
    headers: dict[str, str],
    dump_dir: Path | None = None,
) -> tuple[list[str], list[str]]:
    candidate_urls: list[str] = []
    candidate_fields: list[str] = []
    for script in scripts:
        script_url = urllib.parse.urljoin(final_url, script)
        try:
            _, _, source = request_text(opener, urllib.request.Request(script_url, headers=headers))
        except Exception as exc:
            print(f"ASSET failed {script_url}: {exc}")
            continue

        if dump_dir:
            dump_dir.mkdir(parents=True, exist_ok=True)
            name = re.sub(r"[^A-Za-z0-9_.-]+", "_", urllib.parse.urlparse(script_url).path.strip("/"))
            (dump_dir / (name or "script.js")).write_text(source, encoding="utf-8")

        for item in detect_candidate_urls(source, script_url):
            if item not in candidate_urls:
                candidate_urls.append(item)
        for item in detect_candidate_fields(source):
            if item not in candidate_fields:
                candidate_fields.append(item)
    return candidate_urls[:20], candidate_fields[:40]


def request_text(opener: urllib.request.OpenerDirector, req: urllib.request.Request) -> tuple[int, str, str]:
    with opener.open(req, timeout=15) as response:
        data = response.read()
        charset = response.headers.get_content_charset() or "utf-8"
        text = data.decode(charset, errors="replace")
        return response.status, response.geturl(), text


def make_login_request(action_url: str, method: str, headers: dict[str, str], payload: dict[str, str]) -> urllib.request.Request:
    content_type = os.getenv("CAMPUS_CONTENT_TYPE", "form").strip().lower()
    if content_type == "json":
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(action_url, data=body, headers=headers, method=method.upper())
        req.add_header("Content-Type", "application/json;charset=UTF-8")
        return req

    encoded = urllib.parse.urlencode(payload)
    if method.lower() == "post":
        req = urllib.request.Request(action_url, data=encoded.encode("utf-8"), headers=headers, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        return req

    separator = "&" if urllib.parse.urlparse(action_url).query else "?"
    return urllib.request.Request(action_url + separator + encoded, headers=headers)


def post_form(
    opener: urllib.request.OpenerDirector,
    url: str,
    headers: dict[str, str],
    payload: dict[str, str],
) -> tuple[int, str, str]:
    req = make_login_request(url, "post", headers, payload)
    return request_text(opener, req)


def handle_raas_flow(
    opener: urllib.request.OpenerDirector,
    base_url: str,
    headers: dict[str, str],
    payload: dict[str, str],
    login_text: str,
) -> int:
    try:
        login_data = json.loads(login_text)
    except json.JSONDecodeError:
        print("RAAS login response is not JSON.")
        return 2

    ret = login_data.get("ret")
    msg = login_data.get("msg", "")
    print(f"RAAS login ret={ret} msg={msg}")
    if ret not in (0, 3, 121, 122):
        return 2

    if ret == 0:
        ack_url = urllib.parse.urljoin(base_url, "api/ack_auth.php")
        post_form(opener, ack_url, headers, payload)

    stat_url = urllib.parse.urljoin(base_url, "api/stat.php")
    for attempt in range(1, 12):
        _, _, stat_text = post_form(opener, stat_url, headers, payload)
        try:
            stat_data = json.loads(stat_text)
        except json.JSONDecodeError:
            print("RAAS stat response is not JSON.")
            return 2
        stat_ret = stat_data.get("ret")
        stat_msg = stat_data.get("msg", "")
        print(f"RAAS stat attempt={attempt} ret={stat_ret} msg={stat_msg}")
        if stat_ret == 0:
            print("Result: login and authentication look successful.")
            return 0
        if stat_ret == 4:
            post_form(opener, urllib.parse.urljoin(base_url, "api/ack_auth.php"), headers, payload)
        if stat_ret not in (2, 3, 4):
            return 2
    print("Result: authentication did not finish before timeout.")
    return 2


def login(
    dry_run: bool = False,
    dump_html: Path | None = None,
    scan_assets: bool = False,
    dump_assets: Path | None = None,
) -> int:
    base_url = os.getenv("CAMPUS_LOGIN_URL", DEFAULT_URL)
    jar = CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) auto-campus-login/1.1",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Referer": base_url,
    }

    status, final_url, html = request_text(opener, urllib.request.Request(base_url, headers=headers))
    if dump_html:
        dump_html.write_text(html, encoding="utf-8")

    parser = LoginPageParser()
    parser.feed(html)
    raas_tp = detect_raas_tp(html)
    raas_mode = False
    template_url = ""

    if not parser.forms and not parser.all_fields and raas_tp:
        template_url = urllib.parse.urljoin(final_url, f"tp/{raas_tp}/")
        _, _, template_html = request_text(opener, urllib.request.Request(template_url, headers=headers))
        parser.feed(template_html)
        raas_mode = True

    if scan_assets:
        urls, fields = scan_script_assets(opener, final_url, parser.scripts, headers, dump_assets)
        if parser.scripts:
            print("SCRIPTS " + ", ".join(urllib.parse.urljoin(final_url, item) for item in parser.scripts))
        if urls:
            print("HINT possible URLs from JS assets:")
            for item in urls:
                print(f"  {item}")
        if fields:
            print("HINT possible field names from JS assets:")
            print("  " + ", ".join(fields))

    form = choose_form(parser.forms, parser.all_fields)

    configured_url = os.getenv("CAMPUS_SUBMIT_URL", "").strip()
    password_encoding = os.getenv("CAMPUS_PASSWORD_ENCODING", "").strip().lower()
    if raas_mode:
        password_encoding = password_encoding or "raas-aes"

    payload = build_payload(
        form,
        require_credentials=not dry_run,
        password_encoding=password_encoding,
    )

    default_raas_submit = "api/login.php" if raas_mode else ""
    action_url = urllib.parse.urljoin(final_url, configured_url or form.action or default_raas_submit or final_url)
    method = os.getenv("CAMPUS_METHOD", "").strip().lower() or form.method
    if (form.synthetic or raas_mode) and not configured_url:
        method = os.getenv("CAMPUS_METHOD", "post").strip().lower()

    print(f"GET {final_url} -> HTTP {status}")
    if template_url:
        print(f"TEMPLATE {template_url}")
    print(f"MODE {'raas-js-page' if raas_mode else 'synthetic-js-page' if form.synthetic else 'html-form'}")
    print(f"SUBMIT {method.upper()} {action_url}")
    print("FIELDS " + ", ".join(sorted(payload)))

    candidates = detect_candidate_urls(html, final_url)
    if form.synthetic and not raas_mode and candidates and not configured_url:
        print("HINT possible submit URLs found in page source:")
        for candidate in candidates:
            print(f"  {candidate}")
        print("If login fails, put the correct one in CAMPUS_SUBMIT_URL.")

    if dry_run:
        return 0

    req = make_login_request(action_url, method, headers, payload)
    status, final_url, text = request_text(opener, req)
    compact = re.sub(r"\s+", " ", text).strip().lower()
    print(f"LOGIN {final_url} -> HTTP {status}")

    if raas_mode:
        return handle_raas_flow(opener, base_url, headers, payload, text)

    if any(word in compact for word in SUCCESS_WORDS) or any(word in text for word in CN_SUCCESS_WORDS):
        print("Result: looks successful.")
        return 0
    if any(word in compact for word in FAIL_WORDS) or any(word in text for word in CN_FAIL_WORDS):
        print("Result: page returned a failure/error hint.")
        return 2

    print("Result: request was sent, but success could not be detected from response text.")
    return 0 if 200 <= status < 400 else 2


def main() -> int:
    load_dotenv(Path(__file__).with_name(".env"))
    arg_parser = argparse.ArgumentParser(description="Auto login to campus network portal.")
    arg_parser.add_argument("--dry-run", action="store_true", help="Detect fields without submitting login.")
    arg_parser.add_argument("--dump-html", type=Path, help="Save the fetched login HTML for debugging.")
    arg_parser.add_argument("--scan-assets", action="store_true", help="Scan referenced JavaScript files for API hints.")
    arg_parser.add_argument("--dump-assets", type=Path, help="Save referenced JavaScript files for debugging.")
    args = arg_parser.parse_args()
    try:
        return login(
            dry_run=args.dry_run,
            dump_html=args.dump_html,
            scan_assets=args.scan_assets,
            dump_assets=args.dump_assets,
        )
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"Network error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Login script failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
