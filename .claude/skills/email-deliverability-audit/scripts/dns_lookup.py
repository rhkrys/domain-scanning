#!/usr/bin/env python3
"""
Self-contained DNS TXT/MX resolver (no third-party packages required).
Speaks raw DNS-over-UDP to a public resolver so the skill works on any
machine, even ones without `dig`/`nslookup`/`dnspython` installed.

Usage:
    python3 dns_lookup.py <domain> [--resolver 1.1.1.1]

Prints a JSON object with: spf_records, dmarc_records, mx_records,
dkim (per selector, for a built-in list of common selectors), and any
lookup errors encountered.
"""
import argparse
import json
import random
import socket
import struct
import sys

DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8"]

# Selectors worth probing blindly, covering the most common ESPs.
COMMON_DKIM_SELECTORS = [
    "google", "default", "selector1", "selector2", "k1", "k2", "k3",
    "dkim", "mail", "smtp", "s1", "s2", "mandrill", "mailgun", "sendgrid",
    "zoho", "mxvault", "everlytickey1", "everlytickey2", "protonmail",
    "protonmail2", "protonmail3", "amazonses", "pm", "mimecast20180924",
]

TYPE_A, TYPE_MX, TYPE_TXT = 1, 15, 16
CLASS_IN = 1


def build_query(name: str, qtype: int) -> bytes:
    qid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    question = b"".join(
        bytes([len(part)]) + part.encode() for part in name.rstrip(".").split(".")
    ) + b"\x00" + struct.pack(">HH", qtype, CLASS_IN)
    return header + question


def parse_name(data: bytes, offset: int):
    labels = []
    seen_offsets = set()
    while True:
        if offset in seen_offsets:
            raise ValueError("DNS name compression loop")
        seen_offsets.add(offset)
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            sub_labels, _ = parse_name(data, pointer)
            labels.extend(sub_labels)
            offset += 2
            break
        offset += 1
        labels.append(data[offset:offset + length].decode(errors="replace"))
        offset += length
    return labels, offset


def query(name: str, qtype: int, resolvers, timeout=4.0):
    packet = build_query(name, qtype)
    last_error = None
    for resolver in resolvers:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(packet, (resolver, 53))
            data, _ = sock.recvfrom(4096)
            sock.close()
            return decode_response(data)
        except (socket.timeout, OSError) as exc:
            last_error = str(exc)
            continue
    raise RuntimeError(f"all resolvers failed: {last_error}")


def decode_response(data: bytes):
    _, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", data[:12])
    rcode = flags & 0x000F
    offset = 12
    for _ in range(qdcount):
        _, offset = parse_name(data, offset)
        offset += 4  # qtype + qclass
    answers = []
    for _ in range(ancount):
        _, offset = parse_name(data, offset)
        rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlength]
        offset += rdlength
        if rtype == TYPE_TXT:
            chunks = []
            pos = 0
            while pos < len(rdata):
                seg_len = rdata[pos]
                chunks.append(rdata[pos + 1:pos + 1 + seg_len].decode(errors="replace"))
                pos += 1 + seg_len
            answers.append({"type": "TXT", "value": "".join(chunks)})
        elif rtype == TYPE_MX:
            preference = struct.unpack(">H", rdata[:2])[0]
            mx_labels, _ = parse_name(data, offset - rdlength + 2)
            answers.append({"type": "MX", "preference": preference, "value": ".".join(mx_labels)})
        elif rtype == TYPE_A:
            answers.append({"type": "A", "value": socket.inet_ntoa(rdata)})
    return {"rcode": rcode, "answers": answers}


def safe_query(name, qtype, resolvers):
    try:
        result = query(name, qtype, resolvers)
        return result, None
    except Exception as exc:  # noqa: BLE001
        return None, str(exc)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("domain")
    parser.add_argument("--resolver", action="append", dest="resolvers", default=None)
    parser.add_argument("--selectors", default="", help="comma-separated extra DKIM selectors to probe")
    args = parser.parse_args()

    resolvers = args.resolvers or DEFAULT_RESOLVERS
    domain = args.domain.strip().lower().rstrip(".")

    result = {"domain": domain, "resolvers_used": resolvers}

    spf, spf_err = safe_query(domain, TYPE_TXT, resolvers)
    result["spf_records"] = [a["value"] for a in spf["answers"]] if spf else []
    if spf_err:
        result["spf_error"] = spf_err

    dmarc, dmarc_err = safe_query(f"_dmarc.{domain}", TYPE_TXT, resolvers)
    result["dmarc_records"] = [a["value"] for a in dmarc["answers"]] if dmarc else []
    if dmarc_err:
        result["dmarc_error"] = dmarc_err

    mx, mx_err = safe_query(domain, TYPE_MX, resolvers)
    result["mx_records"] = (
        sorted([{"preference": a["preference"], "host": a["value"]} for a in mx["answers"]],
               key=lambda r: r["preference"])
        if mx else []
    )
    if mx_err:
        result["mx_error"] = mx_err

    selectors = list(COMMON_DKIM_SELECTORS)
    if args.selectors:
        selectors.extend(s.strip() for s in args.selectors.split(",") if s.strip())

    dkim_found = {}
    for selector in selectors:
        dkim_name = f"{selector}._domainkey.{domain}"
        dkim, dkim_err = safe_query(dkim_name, TYPE_TXT, resolvers)
        if dkim and dkim["answers"]:
            dkim_found[selector] = [a["value"] for a in dkim["answers"]]
    result["dkim_records_found"] = dkim_found
    result["dkim_selectors_probed"] = selectors

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    sys.exit(main())
