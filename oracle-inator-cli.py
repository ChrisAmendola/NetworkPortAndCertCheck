#!/usr/bin/env python3
"""oracle-inator-cli.py

Command-line network port + TLS certificate scanner (no GUI / no tkinter).

A headless counterpart to oracle-inator.py. Feed it targets from one or more
CSV files and/or the command line, scan them concurrently, and export the
findings to a CSV file and a professional HTML report.

Features:
  * Targets from CSV files (hostname, ip, port; header optional) and/or -t.
  * Optional global port list (-p) that overrides each target's port.
  * Concurrent scanning with ThreadPoolExecutor.
  * Live per-target completion updates on stdout.
  * Logging to scanner.log (and console at a configurable verbosity).
  * Proper DNS resolution (falls back to a provided IP).
  * Hostname/IP consistency check when both are supplied.
  * TLS handshake detection with SNI.
  * STARTTLS detection/negotiation (SMTP/IMAP/POP3/FTP).
  * Certificate extraction (subject, issuer, validity, SAN, fingerprint, ...).
  * TLS protocol version and negotiated cipher logging.
  * Full exception stack traces captured per target.
  * CSV export with certificate details and errors + HTML report.

Examples:
  python oracle-inator-cli.py -f sample_targets.csv
  python oracle-inator-cli.py -t example.com -t 192.0.2.10,,8443 -p 443,8443
  python oracle-inator-cli.py -f hosts.csv -p 80,443,8000-8010 -w 50 -v

Requires: cryptography  (pip install cryptography)
"""

from __future__ import annotations

import argparse
import csv
import logging
import os
import socket
import ssl
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from html import escape
from typing import Optional

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import ExtensionOID, NameOID
    HAVE_CRYPTOGRAPHY = True
except Exception:  # pragma: no cover - optional dependency
    HAVE_CRYPTOGRAPHY = False


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #
LOG_FILE = "scanner.log"
logger = logging.getLogger("oracle-inator")


def setup_logging(log_file: str = LOG_FILE, console_level: int = logging.WARNING) -> None:
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)-8s] %(threadName)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setLevel(console_level)
    ch.setFormatter(fmt)
    logger.addHandler(ch)


# --------------------------------------------------------------------------- #
# STARTTLS protocol map
# --------------------------------------------------------------------------- #
# Ports where TLS is *not* immediate; the connection begins in plaintext and is
# upgraded via a protocol-specific command.
STARTTLS_PORTS = {
    21: "ftp",
    25: "smtp",
    110: "pop3",
    143: "imap",
    587: "smtp",
    3306: "mysql",       # detection only (advertisement)
    5432: "postgres",    # detection only (advertisement)
}

# Ports where TLS is expected to be immediate (implicit TLS).
IMPLICIT_TLS_PORTS = {443, 465, 636, 993, 995, 990, 8443, 9443, 563, 6697}

DEFAULT_TIMEOUT = 6.0


def parse_port_list(text: str) -> list[int]:
    """Parse a comma/space separated list of ports and ranges.

    Accepts values like "80,443,8000-8010" or "22 80 443". Ranges use a
    hyphen. Returns a de-duplicated, order-preserving list of valid ports.
    Raises ValueError on malformed input or out-of-range ports.
    """
    ports: list[int] = []
    cleaned = text.replace(";", ",").replace(" ", ",")
    for part in cleaned.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi:
                lo, hi = hi, lo
            ports.extend(range(lo, hi + 1))
        else:
            ports.append(int(part))
    seen: set[int] = set()
    out: list[int] = []
    for p in ports:
        if not (1 <= p <= 65535):
            raise ValueError(f"Port out of range (1-65535): {p}")
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class ScanResult:
    hostname: str
    ip: str
    port: int
    resolved_ip: str = ""
    resolved_ips: str = ""
    dns_match: str = ""  # match | mismatch | unresolved | skipped
    port_open: bool = False
    tls: bool = False
    starttls: bool = False
    starttls_available: bool = False
    tls_version: str = ""
    cipher: str = ""
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_serial: str = ""
    cert_not_before: str = ""
    cert_not_after: str = ""
    cert_days_remaining: str = ""
    cert_sans: str = ""
    cert_sig_algo: str = ""
    cert_fingerprint_sha256: str = ""
    cert_self_signed: str = ""
    status: str = "pending"
    error: str = ""
    traceback: str = field(default="", repr=False)


# --------------------------------------------------------------------------- #
# Networking helpers
# --------------------------------------------------------------------------- #
def resolve_host(hostname: str, fallback_ip: str) -> str:
    """Resolve hostname to an IP, falling back to the provided IP."""
    host = (hostname or "").strip()
    if host:
        try:
            info = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
            addr = info[0][4][0]
            logger.debug("DNS resolved %s -> %s", host, addr)
            return addr
        except Exception as exc:
            logger.debug("DNS resolution failed for %s: %s", host, exc)
    fallback = (fallback_ip or "").strip()
    if fallback:
        logger.debug("Using fallback IP %s for %s", fallback, host or "<no-host>")
    return fallback


def resolve_all_ips(hostname: str) -> list[str]:
    """Return every IP address a hostname resolves to (IPv4 + IPv6)."""
    host = (hostname or "").strip()
    if not host:
        return []
    try:
        info = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        seen: set[str] = set()
        addrs: list[str] = []
        for entry in info:
            addr = entry[4][0]
            if addr not in seen:
                seen.add(addr)
                addrs.append(addr)
        return addrs
    except Exception as exc:
        logger.debug("DNS resolution failed for %s: %s", host, exc)
        return []


def check_port_open(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception as exc:
        logger.debug("Port closed/unreachable %s:%s (%s)", ip, port, exc)
        return False


def _recv_line(sock: socket.socket) -> str:
    """Read a single line (best effort) from a plaintext socket."""
    data = b""
    try:
        while b"\n" not in data and len(data) < 4096:
            chunk = sock.recv(1024)
            if not chunk:
                break
            data += chunk
    except Exception:
        pass
    return data.decode("latin-1", errors="replace").strip()


def negotiate_starttls(sock: socket.socket, proto: str, hostname: str) -> bool:
    """Perform the plaintext handshake that upgrades a connection to TLS.

    Returns True if the server acknowledged the STARTTLS request.
    """
    sock.settimeout(DEFAULT_TIMEOUT)
    proto = proto.lower()
    try:
        if proto == "smtp":
            _recv_line(sock)  # banner
            sock.sendall(b"EHLO oracle-inator.local\r\n")
            resp = _recv_line(sock)
            if "STARTTLS" not in resp.upper():
                logger.debug("SMTP server did not advertise STARTTLS: %s", resp[:120])
            sock.sendall(b"STARTTLS\r\n")
            reply = _recv_line(sock)
            return reply.startswith("220")
        if proto == "imap":
            _recv_line(sock)  # banner
            sock.sendall(b"a1 STARTTLS\r\n")
            reply = _recv_line(sock)
            return "OK" in reply.upper()
        if proto == "pop3":
            _recv_line(sock)  # banner
            sock.sendall(b"STLS\r\n")
            reply = _recv_line(sock)
            return reply.startswith("+OK")
        if proto == "ftp":
            _recv_line(sock)  # banner
            sock.sendall(b"AUTH TLS\r\n")
            reply = _recv_line(sock)
            return reply.startswith("234")
    except Exception as exc:
        logger.debug("STARTTLS negotiation error (%s): %s", proto, exc)
        return False
    return False


def probe_starttls_advertised(ip: str, port: int, proto: str, hostname: str) -> bool:
    """Lightweight check: does the server advertise STARTTLS capability?"""
    try:
        with socket.create_connection((ip, port), timeout=DEFAULT_TIMEOUT) as sock:
            sock.settimeout(DEFAULT_TIMEOUT)
            proto = proto.lower()
            if proto == "smtp":
                _recv_line(sock)
                sock.sendall(b"EHLO oracle-inator.local\r\n")
                return "STARTTLS" in _recv_line(sock).upper()
            if proto == "imap":
                banner = _recv_line(sock)
                sock.sendall(b"a1 CAPABILITY\r\n")
                return "STARTTLS" in (banner + _recv_line(sock)).upper()
            if proto == "pop3":
                _recv_line(sock)
                sock.sendall(b"CAPA\r\n")
                return "STLS" in _recv_line(sock).upper()
            if proto == "ftp":
                _recv_line(sock)
                sock.sendall(b"FEAT\r\n")
                return "AUTH TLS" in _recv_line(sock).upper()
    except Exception as exc:
        logger.debug("STARTTLS advertisement probe failed %s:%s (%s)", ip, port, exc)
    return False


def build_ssl_context() -> ssl.SSLContext:
    """A permissive context so we can capture certs even if self-signed/expired."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def perform_tls(result: ScanResult) -> None:
    """Attempt a TLS handshake (direct or via STARTTLS) and extract cert info."""
    ip = result.resolved_ip
    port = result.port
    sni = (result.hostname or "").strip() or None
    ctx = build_ssl_context()

    proto = STARTTLS_PORTS.get(port)
    use_starttls_first = proto in {"ftp", "smtp", "pop3", "imap"}

    raw_sock: Optional[socket.socket] = None
    ssl_sock: Optional[ssl.SSLSocket] = None
    try:
        raw_sock = socket.create_connection((ip, port), timeout=DEFAULT_TIMEOUT)
        raw_sock.settimeout(DEFAULT_TIMEOUT)

        if use_starttls_first:
            acked = negotiate_starttls(raw_sock, proto, result.hostname)
            result.starttls_available = acked
            if not acked:
                logger.debug("STARTTLS not acknowledged on %s:%s", ip, port)
                result.status = "port open (no STARTTLS)"
                return
            result.starttls = True

        ssl_sock = ctx.wrap_socket(raw_sock, server_hostname=sni)
        result.tls = True
        result.tls_version = ssl_sock.version() or ""
        cipher = ssl_sock.cipher()
        if cipher:
            result.cipher = f"{cipher[0]} ({cipher[2]}-bit, {cipher[1]})"
        logger.info(
            "TLS OK %s:%s proto=%s cipher=%s",
            ip, port, result.tls_version, result.cipher,
        )

        der = ssl_sock.getpeercert(binary_form=True)
        if der:
            extract_certificate(der, result)
        else:
            logger.debug("No peer certificate returned for %s:%s", ip, port)

        if result.status in ("pending", ""):
            result.status = "TLS + cert" if result.cert_subject else "TLS (no cert)"

    finally:
        for s in (ssl_sock, raw_sock):
            try:
                if s is not None:
                    s.close()
            except Exception:
                pass


def extract_certificate(der: bytes, result: ScanResult) -> None:
    """Parse a DER-encoded certificate into the result fields."""
    if not HAVE_CRYPTOGRAPHY:
        result.cert_subject = "(install 'cryptography' for cert details)"
        return
    try:
        cert = x509.load_der_x509_certificate(der)
        result.cert_subject = _name_to_str(cert.subject)
        result.cert_issuer = _name_to_str(cert.issuer)
        result.cert_serial = format(cert.serial_number, "x")
        try:
            nb = cert.not_valid_before_utc
            na = cert.not_valid_after_utc
        except AttributeError:  # older cryptography
            nb = cert.not_valid_before.replace(tzinfo=timezone.utc)
            na = cert.not_valid_after.replace(tzinfo=timezone.utc)
        result.cert_not_before = nb.strftime("%Y-%m-%d %H:%M:%S UTC")
        result.cert_not_after = na.strftime("%Y-%m-%d %H:%M:%S UTC")
        result.cert_days_remaining = str((na - datetime.now(timezone.utc)).days)
        result.cert_self_signed = str(cert.issuer == cert.subject)
        try:
            result.cert_sig_algo = cert.signature_algorithm_oid._name
        except Exception:
            result.cert_sig_algo = ""
        try:
            fp = cert.fingerprint(hashes.SHA256())
            result.cert_fingerprint_sha256 = ":".join(f"{b:02X}" for b in fp)
        except Exception:
            pass
        try:
            ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            sans = ext.value.get_values_for_type(x509.DNSName)
            result.cert_sans = ", ".join(sans)
        except Exception:
            result.cert_sans = ""
    except Exception:
        result.traceback += traceback.format_exc()
        logger.exception("Certificate parsing failed for %s:%s", result.ip, result.port)


def _name_to_str(name) -> str:
    parts = []
    try:
        cn = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn:
            parts.append(f"CN={cn[0].value}")
        org = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        if org:
            parts.append(f"O={org[0].value}")
    except Exception:
        pass
    if not parts:
        try:
            return name.rfc4514_string()
        except Exception:
            return str(name)
    return ", ".join(parts)


def scan_target(result: ScanResult) -> ScanResult:
    """Scan a single target: DNS -> port -> TLS/STARTTLS -> certificate."""
    try:
        logger.info("Scanning %s (%s):%s", result.hostname, result.ip, result.port)

        host = (result.hostname or "").strip()
        provided_ip = (result.ip or "").strip()
        dns_ips = resolve_all_ips(host) if host else []
        result.resolved_ips = ", ".join(dns_ips)

        # Verify hostname/IP agreement only when BOTH were provided.
        if host and provided_ip:
            if not dns_ips:
                result.dns_match = "unresolved"
                logger.warning("DNS check: %s did not resolve; cannot verify "
                               "against provided IP %s", host, provided_ip)
            elif provided_ip in dns_ips:
                result.dns_match = "match"
                logger.info("DNS check OK: %s resolves to provided IP %s",
                            host, provided_ip)
            else:
                result.dns_match = "mismatch"
                note = (f"DNS mismatch: {host} resolves to "
                        f"{', '.join(dns_ips)}, not provided IP {provided_ip}")
                logger.warning(note)
                result.error = (result.error + " | " + note) if result.error else note
        else:
            result.dns_match = "skipped"

        result.resolved_ip = resolve_host(result.hostname, result.ip)
        if not result.resolved_ip:
            result.status = "no address"
            result.error = "Could not resolve hostname and no IP provided"
            logger.warning("%s", result.error)
            return result

        result.port_open = check_port_open(result.resolved_ip, result.port)
        if not result.port_open:
            result.status = "port closed"
            return result

        proto = STARTTLS_PORTS.get(result.port)
        # Try TLS (implicit or STARTTLS depending on port).
        try:
            perform_tls(result)
        except ssl.SSLError as exc:
            result.error = f"TLS error: {exc}"
            result.traceback += traceback.format_exc()
            logger.debug("TLS handshake failed %s:%s (%s)",
                         result.resolved_ip, result.port, exc)
            if result.status in ("pending", ""):
                result.status = "port open (no TLS)"
        except Exception as exc:
            result.error = f"{type(exc).__name__}: {exc}"
            result.traceback += traceback.format_exc()
            logger.exception("Unexpected error during TLS on %s:%s",
                             result.resolved_ip, result.port)
            if result.status in ("pending", ""):
                result.status = "port open (error)"

        # If not a TLS/STARTTLS port and TLS did not succeed, probe advertisement.
        if not result.tls and proto in {"smtp", "imap", "pop3", "ftp"} \
                and not result.starttls_available:
            result.starttls_available = probe_starttls_advertised(
                result.resolved_ip, result.port, proto, result.hostname
            )

        if result.status in ("pending", ""):
            result.status = "port open (no TLS)"
        return result
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        result.traceback += traceback.format_exc()
        result.status = "error"
        logger.exception("Fatal error scanning %s:%s", result.hostname, result.port)
        return result


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
CSV_FIELDS = [
    "hostname", "ip", "resolved_ip", "resolved_ips", "dns_match",
    "port", "port_open", "tls", "starttls",
    "starttls_available", "tls_version", "cipher", "cert_subject", "cert_issuer",
    "cert_serial", "cert_not_before", "cert_not_after", "cert_days_remaining",
    "cert_sans", "cert_sig_algo", "cert_fingerprint_sha256", "cert_self_signed",
    "status", "error",
]


def timestamp_slug() -> str:
    return datetime.now().strftime("%d%m%y_%H%M")


def write_csv(results: list[ScanResult], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for r in results:
            row = asdict(r)
            writer.writerow({k: row.get(k, "") for k in CSV_FIELDS})
    logger.info("CSV report written: %s", path)


def _badge(text: str, kind: str) -> str:
    return f'<span class="badge {kind}">{escape(text)}</span>'


def write_html(results: list[ScanResult], path: str, source: str) -> None:
    total = len(results)
    open_ports = sum(1 for r in results if r.port_open)
    tls_ok = sum(1 for r in results if r.tls)
    starttls_ok = sum(1 for r in results if r.starttls)
    errors = sum(1 for r in results if r.error)
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows = []
    for r in results:
        if r.tls:
            status_badge = _badge(r.status, "ok")
        elif r.port_open:
            status_badge = _badge(r.status, "warn")
        else:
            status_badge = _badge(r.status, "bad")

        days = r.cert_days_remaining
        cert_cls = ""
        if days.lstrip("-").isdigit():
            d = int(days)
            if d < 0:
                cert_cls = "bad"
            elif d < 30:
                cert_cls = "warn"
            else:
                cert_cls = "ok"
        expiry = ""
        if r.cert_not_after:
            expiry = (f'{escape(r.cert_not_after)}<br>'
                      f'<span class="badge {cert_cls}">{escape(days)} days</span>')

        err = ""
        if r.error:
            err = f'<details><summary>error</summary><pre>{escape(r.error)}'
            if r.traceback:
                err += "\n\n" + escape(r.traceback)
            err += "</pre></details>"

        rows.append(f"""
        <tr>
          <td>{escape(r.hostname or '-')}</td>
          <td>{escape(r.resolved_ip or r.ip or '-')}</td>
          <td>{r.port}</td>
          <td>{status_badge}</td>
          <td>{escape(r.tls_version or '-')}</td>
          <td class="mono">{escape(r.cipher or '-')}</td>
          <td>{escape(r.cert_subject or '-')}</td>
          <td>{escape(r.cert_issuer or '-')}</td>
          <td>{expiry or '-'}</td>
          <td class="mono small">{escape(r.cert_fingerprint_sha256 or '-')}</td>
          <td>{err or '-'}</td>
        </tr>""")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Oracle-inator Scan Report</title>
<style>
  :root {{
    --bg:#0f172a; --card:#1e293b; --ink:#e2e8f0; --muted:#94a3b8;
    --accent:#38bdf8; --ok:#22c55e; --warn:#f59e0b; --bad:#ef4444; --line:#334155;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--ink);
    font-family:"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }}
  header {{ padding:28px 32px; background:linear-gradient(120deg,#0ea5e9,#6366f1);
    color:#fff; }}
  header h1 {{ margin:0 0 4px; font-size:26px; letter-spacing:.5px; }}
  header p {{ margin:0; opacity:.9; font-size:13px; }}
  .wrap {{ padding:24px 32px 48px; }}
  .cards {{ display:flex; gap:16px; flex-wrap:wrap; margin-bottom:24px; }}
  .card {{ background:var(--card); border:1px solid var(--line); border-radius:12px;
    padding:16px 20px; min-width:150px; flex:1; }}
  .card .n {{ font-size:30px; font-weight:700; }}
  .card .l {{ color:var(--muted); font-size:12px; text-transform:uppercase;
    letter-spacing:.6px; }}
  table {{ width:100%; border-collapse:collapse; background:var(--card);
    border:1px solid var(--line); border-radius:12px; overflow:hidden; }}
  th,td {{ padding:10px 12px; text-align:left; border-bottom:1px solid var(--line);
    font-size:13px; vertical-align:top; }}
  th {{ background:#0b1220; color:var(--muted); text-transform:uppercase;
    font-size:11px; letter-spacing:.6px; position:sticky; top:0; }}
  tr:hover td {{ background:rgba(56,189,248,.06); }}
  .badge {{ display:inline-block; padding:2px 8px; border-radius:999px;
    font-size:11px; font-weight:600; }}
  .badge.ok {{ background:rgba(34,197,94,.15); color:#4ade80; }}
  .badge.warn {{ background:rgba(245,158,11,.15); color:#fbbf24; }}
  .badge.bad {{ background:rgba(239,68,68,.15); color:#f87171; }}
  .mono {{ font-family:"Consolas",monospace; }}
  .small {{ font-size:11px; word-break:break-all; }}
  pre {{ white-space:pre-wrap; font-size:11px; color:var(--muted); margin:6px 0 0; }}
  details summary {{ cursor:pointer; color:var(--accent); }}
  footer {{ color:var(--muted); font-size:12px; padding:0 32px 32px; }}
</style>
</head>
<body>
  <header>
    <h1>Oracle-inator &mdash; Network &amp; TLS Scan Report</h1>
    <p>Generated {escape(generated)} &nbsp;&bull;&nbsp; Source: {escape(source)}</p>
  </header>
  <div class="wrap">
    <div class="cards">
      <div class="card"><div class="n">{total}</div><div class="l">Targets</div></div>
      <div class="card"><div class="n">{open_ports}</div><div class="l">Ports Open</div></div>
      <div class="card"><div class="n">{tls_ok}</div><div class="l">TLS Services</div></div>
      <div class="card"><div class="n">{starttls_ok}</div><div class="l">STARTTLS Upgraded</div></div>
      <div class="card"><div class="n">{errors}</div><div class="l">Errors</div></div>
    </div>
    <table>
      <thead>
        <tr>
          <th>Hostname</th><th>IP</th><th>Port</th><th>Status</th>
          <th>TLS Ver</th><th>Cipher</th><th>Subject</th><th>Issuer</th>
          <th>Expires</th><th>SHA-256 Fingerprint</th><th>Error</th>
        </tr>
      </thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
  </div>
  <footer>Report produced by oracle-inator-cli.py</footer>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    logger.info("HTML report written: %s", path)


# --------------------------------------------------------------------------- #
# Target ingestion
# --------------------------------------------------------------------------- #
def parse_csv_targets(path: str) -> list[dict]:
    """Parse a CSV of hostname, ip, port (header optional).

    The port column may be blank/absent (port -> None) when a global port
    list is supplied on the command line.
    """
    targets: list[dict] = []
    with open(path, newline="", encoding="utf-8-sig") as fh:
        sample = fh.read(2048)
        fh.seek(0)
        has_header = False
        try:
            has_header = csv.Sniffer().has_header(sample)
        except Exception:
            pass
        rows = list(csv.reader(fh))
    if not rows:
        return targets

    start = 0
    header = [c.strip().lower() for c in rows[0]]
    idx = {"hostname": 0, "ip": 1, "port": 2}
    if has_header or {"hostname", "ip", "port"} & set(header):
        start = 1
        for key in idx:
            if key in header:
                idx[key] = header.index(key)

    for row in rows[start:]:
        if not row or all(not c.strip() for c in row):
            continue
        hostname = row[idx["hostname"]].strip() if len(row) > idx["hostname"] else ""
        ip = row[idx["ip"]].strip() if len(row) > idx["ip"] else ""
        port_raw = row[idx["port"]].strip() if len(row) > idx["port"] else ""
        port: Optional[int] = None
        if port_raw:
            try:
                port = int(port_raw)
            except ValueError:
                logger.warning("Skipping row with bad port: %r", row)
                continue
        if not hostname and not ip:
            logger.warning("Skipping row with no host/ip: %r", row)
            continue
        targets.append({"hostname": hostname, "ip": ip, "port": port})
    return targets


def parse_target_spec(spec: str) -> dict:
    """Parse a manual target spec.

    Accepts:
      "hostname"                      -> host only
      "hostname:port"                 -> host + port (single colon only)
      "hostname,ip,port"              -> CSV-style (ip/port optional)
    IPv6 literals with ports must use the comma form.
    """
    spec = spec.strip()
    if "," in spec:
        parts = [p.strip() for p in spec.split(",")]
        hostname = parts[0] if len(parts) > 0 else ""
        ip = parts[1] if len(parts) > 1 else ""
        port: Optional[int] = None
        if len(parts) > 2 and parts[2]:
            port = int(parts[2])
        if not hostname and not ip:
            raise ValueError(f"target has no hostname or IP: {spec!r}")
        return {"hostname": hostname, "ip": ip, "port": port}

    if spec.count(":") == 1:
        host, port_s = spec.split(":", 1)
        return {"hostname": host.strip(), "ip": "", "port": int(port_s)}

    return {"hostname": spec, "ip": "", "port": None}


def build_jobs(targets: list[dict], port_list: list[int]) -> list[dict]:
    """Expand targets into concrete (host, ip, port) scan jobs."""
    jobs: list[dict] = []
    for t in targets:
        if port_list:
            ports = port_list
        elif t.get("port"):
            ports = [int(t["port"])]
        else:
            logger.warning("Skipping %s/%s: no port and no --ports given",
                           t.get("hostname"), t.get("ip"))
            continue
        for p in ports:
            jobs.append({"hostname": t.get("hostname", ""),
                         "ip": t.get("ip", ""), "port": p})
    return jobs


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oracle-inator-cli.py",
        description="Headless network port + TLS certificate scanner.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python oracle-inator-cli.py -f sample_targets.csv\n"
            "  python oracle-inator-cli.py -t example.com:443 -t host,10.0.0.5,8443\n"
            "  python oracle-inator-cli.py -f hosts.csv -p 80,443,8000-8010 -w 50 -v\n"
        ),
    )
    parser.add_argument("-f", "--csv", action="append", default=[], metavar="PATH",
                        help="CSV file with hostname,ip,port (repeatable)")
    parser.add_argument("-t", "--target", action="append", default=[], metavar="SPEC",
                        help="Manual target: 'host', 'host:port', or "
                             "'host,ip,port' (repeatable)")
    parser.add_argument("-p", "--ports", metavar="LIST",
                        help="Port list applied to every target, e.g. "
                             "'443,8443,8000-8010'. Overrides per-target ports.")
    parser.add_argument("-w", "--threads", type=int, default=20, metavar="N",
                        help="Concurrent worker threads (default: 20)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        metavar="SEC", help=f"Socket timeout seconds "
                                            f"(default: {DEFAULT_TIMEOUT})")
    parser.add_argument("-o", "--output-prefix", metavar="NAME",
                        help="Report basename (default: scan_ddmmyy_hhmm)")
    parser.add_argument("--csv-out", metavar="PATH", help="Explicit CSV output path")
    parser.add_argument("--html-out", metavar="PATH", help="Explicit HTML output path")
    parser.add_argument("--no-csv", action="store_true", help="Do not write CSV report")
    parser.add_argument("--no-html", action="store_true", help="Do not write HTML report")
    parser.add_argument("--log-file", default=LOG_FILE, metavar="PATH",
                        help=f"Log file path (default: {LOG_FILE})")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Increase console verbosity (-v INFO, -vv DEBUG)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress the live per-target progress output")
    return parser


def _fmt_result_line(idx: int, total: int, r: ScanResult) -> str:
    target = f"{r.hostname or r.ip}:{r.port}"
    bits = [r.status]
    if r.tls_version:
        bits.append(r.tls_version)
    if r.cert_days_remaining:
        bits.append(f"cert {r.cert_days_remaining}d")
    if r.dns_match == "mismatch":
        bits.append("DNS MISMATCH")
    return f"[{idx}/{total}] {target:<40} {' | '.join(bits)}"


def run_scan(jobs: list[dict], threads: int, quiet: bool) -> list[ScanResult]:
    results: list[ScanResult] = []
    total = len(jobs)
    max_workers = max(1, min(threads, total))
    logger.info("Starting scan of %d job(s) with %d worker(s)", total, max_workers)
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="scan") as pool:
        futures = {}
        for job in jobs:
            res = ScanResult(hostname=job["hostname"], ip=job["ip"],
                             port=int(job["port"]))
            futures[pool.submit(scan_target, res)] = res
        completed = 0
        for future in as_completed(futures):
            completed += 1
            try:
                res = future.result()
            except Exception as exc:
                logger.exception("Worker crashed: %s", exc)
                continue
            results.append(res)
            if not quiet:
                print(_fmt_result_line(completed, total, res), flush=True)
    return results


def print_summary(results: list[ScanResult]) -> None:
    total = len(results)
    open_ports = sum(1 for r in results if r.port_open)
    tls_ok = sum(1 for r in results if r.tls)
    starttls_ok = sum(1 for r in results if r.starttls)
    errors = sum(1 for r in results if r.error)
    mismatches = sum(1 for r in results if r.dns_match == "mismatch")
    print("\n" + "=" * 52)
    print("  SCAN SUMMARY")
    print("=" * 52)
    print(f"  Targets scanned : {total}")
    print(f"  Ports open      : {open_ports}")
    print(f"  TLS services    : {tls_ok}")
    print(f"  STARTTLS upgrade: {starttls_ok}")
    print(f"  DNS mismatches  : {mismatches}")
    print(f"  Errors          : {errors}")
    print("=" * 52)


def main(argv: Optional[list[str]] = None) -> int:
    global DEFAULT_TIMEOUT
    args = build_parser().parse_args(argv)

    console_level = logging.WARNING
    if args.verbose == 1:
        console_level = logging.INFO
    elif args.verbose >= 2:
        console_level = logging.DEBUG
    setup_logging(args.log_file, console_level)

    DEFAULT_TIMEOUT = args.timeout

    logger.info("oracle-inator-cli starting up")
    if not HAVE_CRYPTOGRAPHY:
        logger.warning("cryptography not installed; certificate details limited")

    # Resolve the port list (if any).
    port_list: list[int] = []
    if args.ports:
        try:
            port_list = parse_port_list(args.ports)
        except ValueError as exc:
            print(f"error: invalid --ports value: {exc}", file=sys.stderr)
            return 2
        if not port_list:
            print("error: --ports produced no valid ports", file=sys.stderr)
            return 2

    # Gather targets from CSV files and manual specs.
    targets: list[dict] = []
    source_parts: list[str] = []
    for csv_path in args.csv:
        if not os.path.isfile(csv_path):
            print(f"error: CSV not found: {csv_path}", file=sys.stderr)
            return 2
        try:
            loaded = parse_csv_targets(csv_path)
        except Exception as exc:
            print(f"error: failed to read {csv_path}: {exc}", file=sys.stderr)
            return 2
        targets.extend(loaded)
        source_parts.append(os.path.basename(csv_path))
        logger.info("Loaded %d target(s) from %s", len(loaded), csv_path)

    for spec in args.target:
        try:
            targets.append(parse_target_spec(spec))
        except ValueError as exc:
            print(f"error: invalid --target {spec!r}: {exc}", file=sys.stderr)
            return 2
    if args.target:
        source_parts.append(f"{len(args.target)} manual target(s)")

    if not targets:
        print("error: no targets. Use -f CSV and/or -t target. See --help.",
              file=sys.stderr)
        return 2

    jobs = build_jobs(targets, port_list)
    if not jobs:
        print("error: nothing to scan (targets have no ports and no --ports "
              "was given).", file=sys.stderr)
        return 2

    print(f"Scanning {len(jobs)} job(s) from {len(targets)} target(s) "
          f"with {min(args.threads, len(jobs))} worker(s)...\n")

    results = run_scan(jobs, args.threads, args.quiet)
    print_summary(results)

    # Write reports.
    slug = timestamp_slug()
    prefix = args.output_prefix or f"scan_{slug}"
    written = []
    if not args.no_csv:
        csv_path = os.path.abspath(args.csv_out or f"{prefix}.csv")
        try:
            write_csv(results, csv_path)
            written.append(csv_path)
        except Exception as exc:
            logger.exception("CSV report failed")
            print(f"error: failed to write CSV: {exc}", file=sys.stderr)
    if not args.no_html:
        html_path = os.path.abspath(args.html_out or f"{prefix}.html")
        source = ", ".join(source_parts) if source_parts else "manual entry"
        try:
            write_html(results, html_path, source)
            written.append(html_path)
        except Exception as exc:
            logger.exception("HTML report failed")
            print(f"error: failed to write HTML: {exc}", file=sys.stderr)

    if written:
        print("\nReports written:")
        for path in written:
            print(f"  {path}")

    logger.info("oracle-inator-cli finished")
    # Non-zero exit if every job errored out.
    return 0 if any(not r.error for r in results) or not results else 1


if __name__ == "__main__":
    sys.exit(main())
