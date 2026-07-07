#!/usr/bin/env python3
"""oracle-inator.py

A GUI-driven network port + TLS certificate scanner.

Features:
  * Tkinter GUI with "Load CSV" and "Start Scan" buttons.
  * Manually add scan targets from within the GUI.
  * CSV input format: hostname, ip, port  (header optional).
  * Concurrent scanning with ThreadPoolExecutor.
  * Live per-target status updates in a table + running completion counter.
  * Debug log pane in the GUI mirrored to scanner.log.
  * Proper DNS resolution (falls back to provided IP).
  * TLS handshake detection with SNI (server name indication).
  * STARTTLS detection/negotiation for common protocols (SMTP/IMAP/POP3/FTP).
  * Certificate extraction (subject, issuer, validity, SAN, fingerprint, ...).
  * TLS protocol version and negotiated cipher logging.
  * Full exception stack traces captured per target.
  * Results exported to scan_ddmmyy_hhmm.csv and a professional
    scan_ddmmyy_hhmm.html report.

Requires: cryptography  (pip install cryptography)
"""

from __future__ import annotations

import csv
import logging
import os
import queue
import socket
import ssl
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from html import escape
from typing import Optional

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

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


def setup_logging() -> None:
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)-8s] %(threadName)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
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


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class ScanResult:
    hostname: str
    ip: str
    port: int
    resolved_ip: str = ""
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
    """Resolve hostname to an IP, falling back to the CSV-provided IP."""
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
    "hostname", "ip", "resolved_ip", "port", "port_open", "tls", "starttls",
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
  <footer>Report produced by oracle-inator.py</footer>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    logger.info("HTML report written: %s", path)


# --------------------------------------------------------------------------- #
# GUI
# --------------------------------------------------------------------------- #
class TextLogHandler(logging.Handler):
    """Route log records into the GUI debug pane via a thread-safe queue."""

    def __init__(self, log_queue: "queue.Queue[str]") -> None:
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.log_queue.put(("log", self.format(record)))
        except Exception:
            pass


class OracleInatorApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Oracle-inator :: Network Port & Certificate Scanner")
        self.root.geometry("1180x720")

        self.targets: list[dict] = []
        self.results: list[ScanResult] = []
        self.source_label = "manual entry"
        self.event_queue: "queue.Queue" = queue.Queue()
        self.scanning = False
        self.completed = 0

        self._build_widgets()
        self._attach_gui_logger()
        self.root.after(100, self._drain_queue)

    # -- UI construction --------------------------------------------------- #
    def _build_widgets(self) -> None:
        toolbar = ttk.Frame(self.root, padding=8)
        toolbar.pack(side=tk.TOP, fill=tk.X)

        self.btn_load = ttk.Button(toolbar, text="Load CSV", command=self.load_csv)
        self.btn_load.pack(side=tk.LEFT, padx=(0, 6))

        self.btn_add = ttk.Button(toolbar, text="Add Target", command=self.add_target_dialog)
        self.btn_add.pack(side=tk.LEFT, padx=6)

        self.btn_remove = ttk.Button(toolbar, text="Remove Selected", command=self.remove_selected)
        self.btn_remove.pack(side=tk.LEFT, padx=6)

        self.btn_clear = ttk.Button(toolbar, text="Clear", command=self.clear_targets)
        self.btn_clear.pack(side=tk.LEFT, padx=6)

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10)

        self.threads_var = tk.IntVar(value=20)
        ttk.Label(toolbar, text="Threads:").pack(side=tk.LEFT)
        ttk.Spinbox(toolbar, from_=1, to=200, width=5,
                    textvariable=self.threads_var).pack(side=tk.LEFT, padx=(4, 10))

        self.btn_scan = ttk.Button(toolbar, text="Start Scan", command=self.start_scan)
        self.btn_scan.pack(side=tk.LEFT, padx=6)

        self.progress = ttk.Progressbar(toolbar, mode="determinate", length=220)
        self.progress.pack(side=tk.RIGHT, padx=6)
        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(toolbar, textvariable=self.status_var).pack(side=tk.RIGHT, padx=6)

        # Split pane: results table on top, debug log on bottom.
        paned = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        table_frame = ttk.Frame(paned)
        paned.add(table_frame, weight=3)

        cols = ("hostname", "ip", "port", "status", "tls", "version",
                "cipher", "subject", "expires")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings")
        headings = {
            "hostname": ("Hostname", 150), "ip": ("IP", 120), "port": ("Port", 60),
            "status": ("Status", 150), "tls": ("TLS", 60), "version": ("Version", 90),
            "cipher": ("Cipher", 200), "subject": ("Cert Subject", 200),
            "expires": ("Expires (days)", 100),
        }
        for c in cols:
            text, width = headings[c]
            self.tree.heading(c, text=text)
            self.tree.column(c, width=width, anchor=tk.W)
        vsb = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.tag_configure("ok", foreground="#15803d")
        self.tree.tag_configure("warn", foreground="#b45309")
        self.tree.tag_configure("bad", foreground="#b91c1c")

        log_frame = ttk.LabelFrame(paned, text="Debug Log")
        paned.add(log_frame, weight=1)
        self.log_text = tk.Text(log_frame, height=10, wrap=tk.NONE,
                                bg="#0b1220", fg="#cbd5e1", insertbackground="#cbd5e1",
                                font=("Consolas", 9))
        log_vsb = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_vsb.set, state=tk.DISABLED)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_vsb.pack(side=tk.RIGHT, fill=tk.Y)

    def _attach_gui_logger(self) -> None:
        handler = TextLogHandler(self.event_queue)
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                                               datefmt="%H:%M:%S"))
        logger.addHandler(handler)

    # -- Target management ------------------------------------------------- #
    def load_csv(self) -> None:
        path = filedialog.askopenfilename(
            title="Select CSV file",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            loaded = self._parse_csv(path)
        except Exception as exc:
            logger.exception("Failed to load CSV %s", path)
            messagebox.showerror("Load CSV", f"Failed to read CSV:\n{exc}")
            return
        for t in loaded:
            self._add_target_row(t)
        self.source_label = os.path.basename(path)
        logger.info("Loaded %d target(s) from %s", len(loaded), path)
        self.status_var.set(f"Loaded {len(loaded)} target(s)")

    def _parse_csv(self, path: str) -> list[dict]:
        targets: list[dict] = []
        with open(path, newline="", encoding="utf-8-sig") as fh:
            sample = fh.read(2048)
            fh.seek(0)
            has_header = False
            try:
                has_header = csv.Sniffer().has_header(sample)
            except Exception:
                pass
            reader = csv.reader(fh)
            rows = list(reader)
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
            try:
                hostname = row[idx["hostname"]].strip() if len(row) > idx["hostname"] else ""
                ip = row[idx["ip"]].strip() if len(row) > idx["ip"] else ""
                port_raw = row[idx["port"]].strip() if len(row) > idx["port"] else ""
                port = int(port_raw)
            except (ValueError, IndexError):
                logger.warning("Skipping malformed CSV row: %r", row)
                continue
            targets.append({"hostname": hostname, "ip": ip, "port": port})
        return targets

    def add_target_dialog(self) -> None:
        dlg = tk.Toplevel(self.root)
        dlg.title("Add Scan Target")
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.resizable(False, False)

        fields = {}
        for i, (label, default) in enumerate(
            [("Hostname", ""), ("IP", ""), ("Port", "443")]
        ):
            ttk.Label(dlg, text=label + ":").grid(row=i, column=0, sticky=tk.E,
                                                  padx=8, pady=6)
            var = tk.StringVar(value=default)
            ttk.Entry(dlg, textvariable=var, width=32).grid(row=i, column=1,
                                                            padx=8, pady=6)
            fields[label.lower()] = var

        def submit() -> None:
            host = fields["hostname"].get().strip()
            ip = fields["ip"].get().strip()
            port_raw = fields["port"].get().strip()
            if not host and not ip:
                messagebox.showwarning("Add Target",
                                       "Provide a hostname or an IP.", parent=dlg)
                return
            try:
                port = int(port_raw)
            except ValueError:
                messagebox.showwarning("Add Target", "Port must be a number.",
                                       parent=dlg)
                return
            self._add_target_row({"hostname": host, "ip": ip, "port": port})
            logger.info("Manually added target %s/%s:%s", host, ip, port)
            dlg.destroy()

        btns = ttk.Frame(dlg)
        btns.grid(row=3, column=0, columnspan=2, pady=(6, 10))
        ttk.Button(btns, text="Add", command=submit).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text="Cancel", command=dlg.destroy).pack(side=tk.LEFT, padx=6)
        dlg.bind("<Return>", lambda _e: submit())

    def _add_target_row(self, target: dict) -> None:
        self.targets.append(target)
        self.tree.insert(
            "", tk.END,
            values=(target["hostname"], target["ip"], target["port"],
                    "pending", "", "", "", "", ""),
        )

    def remove_selected(self) -> None:
        if self.scanning:
            return
        selected = self.tree.selection()
        for item in selected:
            index = self.tree.index(item)
            self.tree.delete(item)
            if 0 <= index < len(self.targets):
                self.targets.pop(index)

    def clear_targets(self) -> None:
        if self.scanning:
            return
        self.targets.clear()
        self.results.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.status_var.set("Idle")
        self.progress["value"] = 0

    # -- Scanning ---------------------------------------------------------- #
    def start_scan(self) -> None:
        if self.scanning:
            return
        if not self.targets:
            messagebox.showinfo("Start Scan", "Load a CSV or add a target first.")
            return
        self.scanning = True
        self.completed = 0
        self.results = []
        self._set_buttons_state(tk.DISABLED)
        self.progress["value"] = 0
        self.progress["maximum"] = len(self.targets)
        self.status_var.set(f"Scanning 0/{len(self.targets)}")

        # Refresh table rows to a clean pending state.
        for item in self.tree.get_children():
            vals = list(self.tree.item(item, "values"))
            vals[3] = "pending"
            self.tree.item(item, values=vals, tags=())

        worker = threading.Thread(target=self._run_scan, name="scan-orchestrator",
                                  daemon=True)
        worker.start()

    def _run_scan(self) -> None:
        items = list(self.tree.get_children())
        max_workers = max(1, min(self.threads_var.get(), len(self.targets)))
        logger.info("Starting scan of %d target(s) with %d worker(s)",
                    len(self.targets), max_workers)
        try:
            with ThreadPoolExecutor(max_workers=max_workers,
                                    thread_name_prefix="scan") as pool:
                future_map = {}
                for item_id, target in zip(items, self.targets):
                    res = ScanResult(hostname=target["hostname"],
                                     ip=target["ip"], port=int(target["port"]))
                    future_map[pool.submit(scan_target, res)] = item_id

                for future in as_completed(future_map):
                    item_id = future_map[future]
                    try:
                        res = future.result()
                    except Exception as exc:
                        logger.exception("Worker crashed: %s", exc)
                        continue
                    self.results.append(res)
                    self.event_queue.put(("result", item_id, res))
        except Exception:
            logger.exception("Scan orchestration failed")
        finally:
            self.event_queue.put(("done", None, None))

    # -- Queue draining (main thread) -------------------------------------- #
    def _drain_queue(self) -> None:
        try:
            while True:
                event = self.event_queue.get_nowait()
                kind = event[0]
                if kind == "log":
                    self._append_log(event[1])
                elif kind == "result":
                    self._apply_result(event[1], event[2])
                elif kind == "done":
                    self._finish_scan()
        except queue.Empty:
            pass
        self.root.after(100, self._drain_queue)

    def _append_log(self, line: str) -> None:
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, line + "\n")
        self.log_text.see(tk.END)
        # Cap the pane so it does not grow unbounded.
        if int(self.log_text.index("end-1c").split(".")[0]) > 2000:
            self.log_text.delete("1.0", "500.0")
        self.log_text.configure(state=tk.DISABLED)

    def _apply_result(self, item_id: str, res: ScanResult) -> None:
        if res.tls:
            tag = "ok"
        elif res.port_open:
            tag = "warn"
        else:
            tag = "bad"
        self.tree.item(
            item_id,
            values=(res.hostname, res.resolved_ip or res.ip, res.port, res.status,
                    "yes" if res.tls else ("STARTTLS" if res.starttls_available else "no"),
                    res.tls_version, res.cipher, res.cert_subject,
                    res.cert_days_remaining),
            tags=(tag,),
        )
        self.completed += 1
        self.progress["value"] = self.completed
        self.status_var.set(f"Scanning {self.completed}/{len(self.targets)}")

    def _finish_scan(self) -> None:
        self.scanning = False
        self._set_buttons_state(tk.NORMAL)
        self.status_var.set(f"Scan complete: {len(self.results)} target(s)")
        logger.info("Scan complete. Writing reports...")
        slug = timestamp_slug()
        csv_path = os.path.abspath(f"scan_{slug}.csv")
        html_path = os.path.abspath(f"scan_{slug}.html")
        try:
            write_csv(self.results, csv_path)
            write_html(self.results, html_path, self.source_label)
        except Exception as exc:
            logger.exception("Report generation failed")
            messagebox.showerror("Reports", f"Failed to write reports:\n{exc}")
            return
        messagebox.showinfo(
            "Scan Complete",
            f"Scanned {len(self.results)} target(s).\n\n"
            f"CSV:  {csv_path}\nHTML: {html_path}",
        )

    def _set_buttons_state(self, state: str) -> None:
        for btn in (self.btn_load, self.btn_add, self.btn_remove,
                    self.btn_clear, self.btn_scan):
            btn.configure(state=state)


def main() -> None:
    setup_logging()
    logger.info("oracle-inator starting up")
    if not HAVE_CRYPTOGRAPHY:
        logger.warning("cryptography not installed; certificate details limited")
    root = tk.Tk()
    OracleInatorApp(root)
    root.mainloop()
    logger.info("oracle-inator shutting down")


if __name__ == "__main__":
    main()
