#!/usr/bin/env python3
"""dbprobe.py

Database-aware service fingerprinting and TLS negotiation, shared by
sql_portcheck_tool.py (GUI) and sql_portcheck_tool_cli.py (CLI).

Databases rarely expose "implicit" TLS the way HTTPS does. Each speaks its own
wire protocol and upgrades to TLS through a protocol-specific handshake:

  * PostgreSQL  - send SSLRequest (0x04D2162F); server replies 'S' or 'N'.
  * MySQL/Maria - read the server greeting; CLIENT_SSL bit signals support;
                  reply with an SSL-request packet then wrap the socket.
  * MSSQL (TDS) - PRELOGIN exchange advertises the ENCRYPTION option; the TLS
                  handshake itself is encapsulated inside TDS packets.
  * Oracle      - TNS listener (plaintext) answers a CONNECT with Accept/
                  Refuse/Resend/Redirect; TCPS is implicit TLS carrying TNS.

Every probe opens its own short-lived connection so a failed attempt never
corrupts another. probe() tries the database protocols first, then falls back
to a direct TLS handshake (labelling Oracle TCPS when TNS answers inside TLS).

The module has no third-party dependencies; certificate bytes (DER) are handed
back to the caller, which already knows how to parse them.
"""

from __future__ import annotations

import socket
import ssl
import struct
from dataclasses import dataclass
from typing import Optional


DEFAULT_TIMEOUT = 6.0


@dataclass
class DBProbeResult:
    service: str = ""             # postgresql | mysql | mariadb | mssql | oracle-tns | oracle-tcps | ""
    service_version: str = ""
    tls_mode: str = ""            # implicit | negotiated | required | supported | none
    tls: bool = False
    tls_version: str = ""
    cipher: str = ""
    cert_der: Optional[bytes] = None
    notes: str = ""


# --------------------------------------------------------------------------- #
# Low-level helpers
# --------------------------------------------------------------------------- #
def _permissive_ctx() -> ssl.SSLContext:
    """Accept self-signed/expired certs and legacy TLS so we can still probe."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1  # allow legacy DB endpoints
    except (ValueError, OSError):
        pass
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    return ctx


def _fmt_cipher(cipher) -> str:
    if not cipher:
        return ""
    return f"{cipher[0]} ({cipher[2]}-bit, {cipher[1]})"


def _recv_some(sock: socket.socket, nbytes: int = 2048) -> bytes:
    try:
        return sock.recv(nbytes)
    except Exception:
        return b""


def _recv_exact(sock: socket.socket, nbytes: int) -> bytes:
    data = b""
    while len(data) < nbytes:
        try:
            chunk = sock.recv(nbytes - len(data))
        except Exception:
            break
        if not chunk:
            break
        data += chunk
    return data


# --------------------------------------------------------------------------- #
# PostgreSQL
# --------------------------------------------------------------------------- #
def probe_postgresql(ip: str, port: int, sni: Optional[str],
                     timeout: float) -> Optional[DBProbeResult]:
    ssl_request = struct.pack("!ii", 8, 80877103)  # length=8, magic code
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
    except Exception:
        return None
    try:
        raw.settimeout(min(timeout, 3.0))  # response is immediate if PostgreSQL
        raw.sendall(ssl_request)
        resp = _recv_exact(raw, 1)
        raw.settimeout(timeout)
        if resp not in (b"S", b"N", b"E"):
            return None  # not PostgreSQL
        res = DBProbeResult(service="postgresql")
        if resp == b"S":
            ctx = _permissive_ctx()
            ssl_sock = ctx.wrap_socket(raw, server_hostname=sni or None)
            try:
                res.tls = True
                res.tls_mode = "negotiated"
                res.tls_version = ssl_sock.version() or ""
                res.cipher = _fmt_cipher(ssl_sock.cipher())
                res.cert_der = ssl_sock.getpeercert(binary_form=True) or None
            finally:
                _quiet_close(ssl_sock)
            raw = None  # owned by ssl_sock now
        else:
            res.tls_mode = "none"
            res.notes = "server rejected SSLRequest ('N')" if resp == b"N" \
                else "server returned error to SSLRequest"
        return res
    except ssl.SSLError as exc:
        return DBProbeResult(service="postgresql", tls_mode="negotiated",
                             notes=f"TLS handshake failed: {exc}")
    except Exception:
        return None
    finally:
        _quiet_close(raw)


# --------------------------------------------------------------------------- #
# MySQL / MariaDB
# --------------------------------------------------------------------------- #
CLIENT_SSL = 0x0800
CLIENT_PROTOCOL_41 = 0x0200
CLIENT_SECURE_CONNECTION = 0x8000


def probe_mysql(ip: str, port: int, sni: Optional[str],
                timeout: float) -> Optional[DBProbeResult]:
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
    except Exception:
        return None
    try:
        # MySQL/MariaDB greet immediately; bound the wait so non-MySQL ports
        # (which stay silent) don't stall for the full timeout.
        raw.settimeout(min(timeout, 2.5))
        header = _recv_exact(raw, 4)
        if len(header) < 4:
            return None
        raw.settimeout(timeout)
        length = header[0] | (header[1] << 8) | (header[2] << 16)
        seq = header[3]
        if length == 0 or length > 4096:
            return None
        payload = _recv_exact(raw, length)
        if len(payload) < 1 or payload[0] != 0x0A:  # protocol version 10
            return None  # not the MySQL/MariaDB handshake

        nul = payload.find(b"\x00", 1)
        if nul == -1:
            return None
        version = payload[1:nul].decode("latin-1", "replace")
        service = "mariadb" if "mariadb" in version.lower() else "mysql"

        # Parse capability flags to learn whether SSL is offered.
        pos = nul + 1 + 4 + 8 + 1  # + conn_id(4) + auth1(8) + filler(1)
        cap_lower = 0
        if len(payload) >= pos + 2:
            cap_lower = payload[pos] | (payload[pos + 1] << 8)
        ssl_supported = bool(cap_lower & CLIENT_SSL)

        res = DBProbeResult(service=service, service_version=version)
        if not ssl_supported:
            res.tls_mode = "none"
            res.notes = "server did not advertise CLIENT_SSL"
            return res

        # Upgrade: send SSL-request packet (seq+1), then TLS-wrap the socket.
        flags = CLIENT_SSL | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION
        body = struct.pack("<IIB", flags, 16777215, 45) + b"\x00" * 23
        pkt = struct.pack("<I", len(body))[:3] + bytes([(seq + 1) & 0xFF]) + body
        raw.sendall(pkt)

        ctx = _permissive_ctx()
        ssl_sock = ctx.wrap_socket(raw, server_hostname=sni or None)
        try:
            res.tls = True
            res.tls_mode = "negotiated"
            res.tls_version = ssl_sock.version() or ""
            res.cipher = _fmt_cipher(ssl_sock.cipher())
            res.cert_der = ssl_sock.getpeercert(binary_form=True) or None
        finally:
            _quiet_close(ssl_sock)
        raw = None
        return res
    except ssl.SSLError as exc:
        return DBProbeResult(service="mysql", tls_mode="negotiated",
                             notes=f"TLS handshake failed: {exc}")
    except Exception:
        return None
    finally:
        _quiet_close(raw)


# --------------------------------------------------------------------------- #
# Microsoft SQL Server (TDS)
# --------------------------------------------------------------------------- #
TDS_PRELOGIN = 0x12
_ENCRYPT_NAMES = {0x00: "off", 0x01: "on", 0x02: "not-supported", 0x03: "required"}


def _tds_send(sock, ttype: int, payload: bytes) -> None:
    header = struct.pack(">BBHHBB", ttype, 0x01, len(payload) + 8, 0, 0, 0)
    sock.sendall(header + payload)


def _tds_recv(sock) -> bytes:
    header = _recv_exact(sock, 8)
    if len(header) < 8:
        return b""
    length = struct.unpack(">H", header[2:4])[0]
    if length < 8:
        return b""
    return _recv_exact(sock, length - 8)


def _build_prelogin() -> bytes:
    # Option table: VERSION(0x00) and ENCRYPTION(0x01), then terminator 0xFF.
    header_len = 5 * 2 + 1
    version_off, version_len = header_len, 6
    enc_off, enc_len = version_off + version_len, 1
    table = (
        bytes([0x00]) + struct.pack(">HH", version_off, version_len)
        + bytes([0x01]) + struct.pack(">HH", enc_off, enc_len)
        + bytes([0xFF])
    )
    data = b"\x00" * version_len + bytes([0x01])  # ENCRYPT_ON request
    return table + data


def _parse_prelogin(payload: bytes) -> tuple[Optional[int], str]:
    """Return (encryption_byte, version_string) from a PRELOGIN response."""
    enc = None
    version = ""
    i = 0
    while i + 5 <= len(payload):
        token = payload[i]
        if token == 0xFF:
            break
        off, ln = struct.unpack(">HH", payload[i + 1:i + 5])
        if token == 0x01 and off < len(payload):  # ENCRYPTION
            enc = payload[off]
        elif token == 0x00 and off + 4 <= len(payload):  # VERSION
            major, minor = payload[off], payload[off + 1]
            build = (payload[off + 2] << 8) | payload[off + 3]
            version = f"{major}.{minor}.{build}"
        i += 5
    return enc, version


def _tds_tls_handshake(sock, sni: Optional[str], timeout: float):
    """Drive a TLS handshake whose records are wrapped in TDS PRELOGIN packets."""
    ctx = _permissive_ctx()
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    sslobj = ctx.wrap_bio(incoming, outgoing, server_hostname=sni or None)
    for _ in range(64):
        try:
            sslobj.do_handshake()
            pending = outgoing.read()
            if pending:
                _tds_send(sock, TDS_PRELOGIN, pending)
            return sslobj
        except ssl.SSLWantReadError:
            pending = outgoing.read()
            if pending:
                _tds_send(sock, TDS_PRELOGIN, pending)
            payload = _tds_recv(sock)
            if not payload:
                raise ssl.SSLError("connection closed during TDS TLS handshake")
            incoming.write(payload)
    raise ssl.SSLError("TDS TLS handshake did not complete")


def probe_mssql(ip: str, port: int, sni: Optional[str],
                timeout: float) -> Optional[DBProbeResult]:
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
    except Exception:
        return None
    try:
        raw.settimeout(min(timeout, 3.0))
        _tds_send(raw, TDS_PRELOGIN, _build_prelogin())
        # A PRELOGIN response is a TDS 'tabular result' packet (type 0x04).
        header = _recv_exact(raw, 8)
        if len(header) < 8 or header[0] != 0x04:
            return None  # not TDS / MSSQL
        raw.settimeout(timeout)
        length = struct.unpack(">H", header[2:4])[0]
        payload = _recv_exact(raw, max(0, length - 8))
        enc, version = _parse_prelogin(payload)

        res = DBProbeResult(service="mssql", service_version=version)
        if enc is None:
            res.tls_mode = "none"
            res.notes = "PRELOGIN response lacked ENCRYPTION option"
            return res
        res.notes = f"ENCRYPTION={_ENCRYPT_NAMES.get(enc, hex(enc))}"
        if enc == 0x02:  # ENCRYPT_NOT_SUP
            res.tls_mode = "none"
            return res

        res.tls_mode = "required" if enc == 0x03 else "negotiated"
        sslobj = _tds_tls_handshake(raw, sni, timeout)
        res.tls = True
        res.tls_version = sslobj.version() or ""
        res.cipher = _fmt_cipher(sslobj.cipher())
        res.cert_der = sslobj.getpeercert(binary_form=True) or None
        return res
    except ssl.SSLError as exc:
        return DBProbeResult(service="mssql", tls_mode="negotiated",
                             notes=f"TDS TLS handshake failed: {exc}")
    except Exception:
        return None
    finally:
        _quiet_close(raw)


# --------------------------------------------------------------------------- #
# Oracle TNS
# --------------------------------------------------------------------------- #
def _build_tns_connect() -> bytes:
    connect_data = (b"(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=))"
                    b"(ADDRESS=(PROTOCOL=TCP)(HOST=127.0.0.1)(PORT=1521)))")
    # Fixed connect header is 58 bytes; connect string follows at offset 58.
    offset = 58
    total = offset + len(connect_data)
    hdr = struct.pack(">H", total)          # packet length
    hdr += struct.pack(">H", 0)             # packet checksum
    hdr += bytes([0x01, 0x00])              # type=CONNECT(1), reserved
    hdr += struct.pack(">H", 0)             # header checksum
    body = struct.pack(
        ">HHHHHHHH",
        0x013B,   # version
        0x012C,   # version (compatible)
        0x0C41,   # service options
        0x2000,   # session data unit
        0xFFFF,   # max transmission data unit
        0x4F98,   # NT protocol characteristics
        0x0000,   # line turnaround
        0x0001,   # value of 1 in hardware (byte order)
    )
    body += struct.pack(">H", len(connect_data))  # connect data length
    body += struct.pack(">H", offset)             # connect data offset
    body += struct.pack(">I", 0x00000800)         # max receivable connect data
    body += bytes([0x00, 0x00])                   # connect flags 0/1
    body += b"\x00" * (offset - 8 - len(body))    # pad trace fields to offset
    return hdr + body + connect_data


def _looks_like_tns(resp: bytes) -> bool:
    if len(resp) >= 5 and resp[4] in (0x02, 0x04, 0x05, 0x0B):
        return True
    return any(tok in resp for tok in (b"(ERROR", b"(DESCRIPTION", b"ORA-", b"TNS"))


def probe_oracle_tns(ip: str, port: int, sni: Optional[str],
                     timeout: float) -> Optional[DBProbeResult]:
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
    except Exception:
        return None
    try:
        raw.settimeout(min(timeout, 3.0))  # a listener replies promptly
        raw.sendall(_build_tns_connect())
        resp = _recv_some(raw, 2048)
        if not resp or not _looks_like_tns(resp):
            return None
        res = DBProbeResult(service="oracle-tns", tls_mode="none")
        res.notes = "TNS listener (plaintext); Oracle Native Network " \
                    "Encryption is negotiated inside TNS and is not TLS"
        return res
    except Exception:
        return None
    finally:
        _quiet_close(raw)


def _confirm_oracle_over_tls(ssl_sock) -> bool:
    """After a TLS handshake, ask TNS a question to confirm Oracle TCPS."""
    try:
        ssl_sock.sendall(_build_tns_connect())
        resp = ssl_sock.recv(2048)
        return _looks_like_tns(resp)
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Direct / implicit TLS (HTTPS-style, and Oracle TCPS)
# --------------------------------------------------------------------------- #
def probe_direct_tls(ip: str, port: int, sni: Optional[str],
                     timeout: float) -> Optional[DBProbeResult]:
    ctx = _permissive_ctx()
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
    except Exception:
        return None
    # Bound the handshake: a protocol that silently swallows the ClientHello
    # (rather than resetting) must not stall the whole probe chain.
    raw.settimeout(min(timeout, 4.0))
    try:
        ssl_sock = ctx.wrap_socket(raw, server_hostname=sni or None)
    except Exception:
        _quiet_close(raw)
        return None
    ssl_sock.settimeout(timeout)
    try:
        res = DBProbeResult(tls=True, tls_mode="implicit")
        res.tls_version = ssl_sock.version() or ""
        res.cipher = _fmt_cipher(ssl_sock.cipher())
        res.cert_der = ssl_sock.getpeercert(binary_form=True) or None
        if _confirm_oracle_over_tls(ssl_sock):
            res.service = "oracle-tcps"
            res.notes = "Oracle TNS answered inside TLS (TCPS)"
        return res
    finally:
        _quiet_close(ssl_sock)


def _quiet_close(sock) -> None:
    try:
        if sock is not None:
            sock.close()
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def probe(ip: str, port: int, hostname: str = "",
          timeout: float = DEFAULT_TIMEOUT, logger=None) -> Optional[DBProbeResult]:
    """Fingerprint the service on an open port and negotiate TLS accordingly.

    Returns a DBProbeResult when either a database is identified or a direct
    TLS handshake succeeds. Returns None when the port is neither (e.g. a
    plaintext or STARTTLS-only service), so the caller can fall back to its
    own STARTTLS handling.
    """
    sni = (hostname or "").strip() or None
    # Direct TLS first: cheaply catches implicit-TLS ports (HTTPS, Oracle TCPS)
    # and fails fast on protocols that need negotiation. The database probes
    # that block on a silent port are tried afterwards.
    probes = (
        ("direct-tls", probe_direct_tls),
        ("postgresql", probe_postgresql),
        ("mssql", probe_mssql),
        ("oracle-tns", probe_oracle_tns),
        ("mysql", probe_mysql),
    )
    for name, fn in probes:
        try:
            result = fn(ip, port, sni, timeout)
        except Exception as exc:
            if logger:
                logger.debug("DB probe %s failed on %s:%s (%s)", name, ip, port, exc)
            continue
        if result is not None:
            if logger:
                logger.info("Service probe %s:%s -> %s%s (tls=%s, mode=%s)",
                            ip, port, result.service or "tls",
                            f" {result.service_version}" if result.service_version else "",
                            result.tls, result.tls_mode)
            return result
    return None
