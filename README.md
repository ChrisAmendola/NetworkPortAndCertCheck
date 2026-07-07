# Oracle-inator

A GUI-driven network port and TLS certificate scanner.

`oracle-inator.py` presents a Tkinter interface that lets you load a list of
targets (or add them by hand), scan them concurrently for open ports, detect
TLS / STARTTLS services, extract certificate details, and export the findings
to a CSV file and a polished HTML report.

## Features

- **GUI** with **Load CSV** and **Start Scan** buttons.
- **Manually add / remove** scan targets from the toolbar.
- **ThreadPoolExecutor** concurrent scanning (thread count is configurable).
- **Live completion updates** with a progress bar and running counter.
- **Per-target status** shown in a color-coded results table.
- **Debug log pane** inside the GUI, mirrored to `scanner.log`.
- **Proper DNS resolution** (falls back to a provided IP when DNS fails).
- **Improved SNI handling** (server name indication uses the hostname).
- **TLS handshake detection** for implicit-TLS ports.
- **STARTTLS detection & negotiation** for SMTP, IMAP, POP3, and FTP.
- **Certificate extraction**: subject, issuer, serial, validity window, days
  remaining, SANs, signature algorithm, SHA-256 fingerprint, self-signed flag.
- **TLS protocol version and negotiated cipher** logging.
- **Full exception stack traces** captured per target and included in reports.
- **CSV export** with all certificate details and errors.
- Professional **HTML report**: `scan_ddmmyy_hhmm.html`.

## Requirements

- Python 3.9+ (developed against 3.12)
- [`cryptography`](https://pypi.org/project/cryptography/) for full certificate
  parsing (the script degrades gracefully if it is missing).
- Tkinter (bundled with standard CPython on Windows/macOS; on some Linux
  distros install `python3-tk`).

```bash
pip install -r requirements.txt
```

## Usage

```bash
python oracle-inator.py
```

1. Click **Load CSV** and pick a file, or use **Add Target** to enter targets
   manually. A sample file, `sample_targets.csv`, is included.
2. (Optional) adjust the **Threads** count.
3. Click **Start Scan**. Watch progress in the table and the debug log pane.
4. When the scan finishes, `scan_<ddmmyy>_<hhmm>.csv` and
   `scan_<ddmmyy>_<hhmm>.html` are written to the working directory.

## CSV input format

A header row is optional. Columns are `hostname, ip, port`:

```csv
hostname,ip,port
example.com,,443
,192.0.2.10,8443
smtp.gmail.com,,587
```

- Provide a `hostname`, an `ip`, or both. If DNS resolution fails, the `ip`
  column is used as a fallback.
- Standard STARTTLS ports (21, 25, 110, 143, 587) trigger a STARTTLS upgrade;
  implicit-TLS ports (443, 465, 636, 993, 995, ...) attempt a direct handshake.

## Output

- `scanner.log` — rolling debug log for every run.
- `scan_<ddmmyy>_<hhmm>.csv` — machine-readable results.
- `scan_<ddmmyy>_<hhmm>.html` — human-friendly report with summary cards and a
  color-coded table (expiring/expired certificates are highlighted).
