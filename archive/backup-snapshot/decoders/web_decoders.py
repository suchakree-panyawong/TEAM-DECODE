from __future__ import annotations
import base64, binascii, html, re, urllib.parse
from core.registry import register_decoder
from core.heuristics import _log_debug, bytes_to_text, is_effectively_binary, has_control_chars

HEX_ESCAPE_RE         = re.compile(r"\\x([0-9A-Fa-f]{2})")
OCTAL_ESCAPE_RE       = re.compile(r"\\([0-7]{1,3})")
HTML_NUMERIC_ENTITY_RE = re.compile(r"&#(x[0-9A-Fa-f]+|[0-9]+);")
HTML_NAMED_ENTITY_RE  = re.compile(r"&([a-zA-Z][a-zA-Z0-9]*);")

def _escape_guard_ok(value: str, matches: list, min_matches: int = 2, min_density: float = 0.15, chars_per_match: int = 4) -> bool:
    return len(matches) >= min_matches or (len(matches) * chars_per_match / max(len(value), 1)) >= min_density

def add_base64_padding(value: str) -> str:
    return value + ("=" * ((4 - len(value) % 4) % 4))

@register_decoder(name="url", category="web")
def decode_url(value: str) -> str | None:
    compact = value.strip()
    if "%" not in compact and "+" not in compact: return None
    escape_matches = re.findall(r"%[0-9A-Fa-f]{2}", compact)
    if not escape_matches or (len(escape_matches) < 2 and (len(escape_matches)*3/max(len(compact),1)) < 0.15): return None
    try: decoded = urllib.parse.unquote(compact, errors="strict")
    except (UnicodeDecodeError, ValueError): return None
    if not decoded or decoded == compact or is_effectively_binary(decoded): return None
    return decoded

@register_decoder(name="punycode", category="web")
def decode_punycode(value: str) -> str | None:
    compact = value.strip()
    if "xn--" not in compact.lower(): return None
    labels = compact.split(".")
    if not any(label.lower().startswith("xn--") for label in labels): return None
    decoded_labels, changed = [], False
    for label in labels:
        if label.lower().startswith("xn--"):
            body = label[4:]
            if not body: return None
            try: decoded_label = body.encode("ascii").decode("punycode")
            except (UnicodeError, LookupError): return None
            decoded_labels.append(decoded_label); changed = True
        else: decoded_labels.append(label)
    if not changed: return None
    res = ".".join(decoded_labels); return res if res and res != compact else None

@register_decoder(name="hex_escape", category="web")
def decode_hex_escape(value: str) -> str | None:
    matches = HEX_ESCAPE_RE.findall(value)
    if not matches or not _escape_guard_ok(value, matches, chars_per_match=4): return None
    decoded = HEX_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), value)
    if not decoded or decoded == value or is_effectively_binary(decoded): return None
    return decoded

@register_decoder(name="octal_escape", category="web")
def decode_octal_escape(value: str) -> str | None:
    matches = OCTAL_ESCAPE_RE.findall(value)
    if not matches or not _escape_guard_ok(value, matches, chars_per_match=3): return None
    try: decoded = OCTAL_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 8)), value)
    except ValueError: return None
    if not decoded or decoded == value or is_effectively_binary(decoded): return None
    return decoded

@register_decoder(name="html_numeric_entity", category="web")
def decode_html_numeric_entity(value: str) -> str | None:
    matches = HTML_NUMERIC_ENTITY_RE.findall(value)
    if not matches or not _escape_guard_ok(value, matches, min_matches=1, chars_per_match=5): return None
    def _sub(m: re.Match) -> str:
        tok = m.group(1); cp = int(tok[1:], 16) if tok[0] in "xX" else int(tok)
        try: return chr(cp)
        except (ValueError, OverflowError): return m.group(0)
    decoded = HTML_NUMERIC_ENTITY_RE.sub(_sub, value)
    if not decoded or decoded == value or has_control_chars(decoded): return None
    return decoded

@register_decoder(name="jwt", category="web")
def decode_jwt(value: str) -> str | None:
    parts = value.strip().split(".")
    if len(parts) != 3 or any(not p or not re.fullmatch(r"[A-Za-z0-9_-]+", p) for p in parts): return None
    try:
        h_raw = base64.urlsafe_b64decode(add_base64_padding(parts[0]))
        p_raw = base64.urlsafe_b64decode(add_base64_padding(parts[1]))
    except (binascii.Error, ValueError): return None
    h_text, p_text = bytes_to_text(h_raw), bytes_to_text(p_raw)
    if not h_text or not p_text or not (h_text.lstrip().startswith("{") and p_text.lstrip().startswith("{")): return None
    return f"header: {h_text} | payload: {p_text}"

@register_decoder(name="html_entity", category="web")
def decode_html_entity(value: str) -> str | None:
    candidates = HTML_NAMED_ENTITY_RE.findall(value)
    if not candidates: return None
    rec = [c for c in candidates if html.unescape(f"&{c};") != f"&{c};"]
    if not rec or not _escape_guard_ok(value, rec, min_matches=1, chars_per_match=4): return None
    decoded = html.unescape(value)
    if not decoded or decoded == value or has_control_chars(decoded): return None
    return decoded

@register_decoder(name="quoted_printable", category="web")
def decode_quoted_printable(value: str) -> str | None:
    if "=" not in value: return None
    has_soft_break = "=\n" in value or "=\r\n" in value
    escape_matches = re.findall(r"=[0-9A-Fa-f]{2}", value)
    if not has_soft_break and len(escape_matches) < 3: return None
    try:
        import quopri; raw = quopri.decodestring(value.encode("latin-1", errors="ignore"))
    except Exception as e: _log_debug(f"decode_quoted_printable: failed: {e!r}"); return None
    decoded = bytes_to_text(raw)
    if not decoded or decoded == value or is_effectively_binary(decoded): return None
    return decoded
