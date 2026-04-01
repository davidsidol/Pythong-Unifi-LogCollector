# UniFi Log Collector (Windows File Server)

Python application to collect syslog from UniFi Network Controller and UniFi APs, then write structured JSONL logs to disk (local path or file share path).

## What it does

- Listens for syslog over UDP and/or TCP.
- Parses common syslog fields (facility, severity, host, app, message).
- Writes logs to:
  - `LOG_DIRECTORY/YYYY-MM-DD/<device>.jsonl`
- Runs on Windows Server as:
  - a foreground process, or
  - a startup scheduled task (included PowerShell helper).

## Files

- `unifi_log_collector.py` - collector app
- `config.ini.example` - config template
- `install_scheduled_task.ps1` - optional install script for Windows startup task

## Requirements

- Windows Server 2019/2022 (or any Windows host)
- Python 3.10+ (3.11+ recommended)
- Firewall rule allowing inbound syslog port from your UniFi subnet

## Setup

1. Copy project files to a folder on the server, for example:
   - `C:\UnifiCollector`
2. Copy config template:
   - `copy config.ini.example config.ini`
3. Edit `config.ini`:
   - Set `port` (`5514` recommended unless you need `514`)
   - Set `log_directory` (local drive or UNC path)
4. Start manually for testing:
   - `python unifi_log_collector.py --config config.ini`

## UniFi Configuration

In the UniFi Network application:

1. Go to `Settings` -> `System` (or `Advanced`, depending on version).
2. Find `Remote Logging` / `Syslog`.
3. Set:
   - Syslog server IP = Windows file server IP
   - Port = your `config.ini` port (for example `5514`)
   - Protocol = UDP (or TCP if enabled in collector)
4. Apply/provision devices.

## Run at startup (Scheduled Task)

From an elevated PowerShell in `C:\UnifiCollector`:

```powershell
.\install_scheduled_task.ps1 `
  -TaskName "UniFi Syslog Collector" `
  -PythonExe "C:\Python311\python.exe" `
  -AppPath "C:\UnifiCollector\unifi_log_collector.py" `
  -ConfigPath "C:\UnifiCollector\config.ini" `
  -RunAsUser "SYSTEM"
```

## Windows Firewall example

Allow inbound UDP 5514:

```powershell
New-NetFirewallRule -DisplayName "UniFi Syslog UDP 5514" -Direction Inbound -Protocol UDP -LocalPort 5514 -Action Allow
```

For TCP:

```powershell
New-NetFirewallRule -DisplayName "UniFi Syslog TCP 5514" -Direction Inbound -Protocol TCP -LocalPort 5514 -Action Allow
```

## Log format

Each line is JSON, for example:

```json
{
  "received_at_utc": "2026-03-03T17:03:21.123456+00:00",
  "source_ip": "10.0.1.34",
  "hostname": "U6-Pro-Lobby",
  "facility": "daemon",
  "severity": "notice",
  "device_timestamp_utc": "2026-03-03T17:03:20+00:00",
  "app": "hostapd",
  "message": "wlan0: STA xx:xx:xx:xx:xx:xx IEEE 802.11: disassociated",
  "raw": "<29>Mar  3 17:03:20 U6-Pro-Lobby hostapd: wlan0: STA xx..."
}
```

## Operational notes

- Port `514` may require elevated rights. Port `5514` avoids privilege issues.
- If using a UNC path (`\\server\share\...`) as `log_directory`, the run account must have write access.
- APs usually send UDP syslog by default.

## TypeScript Nmap Scanner

This repo now also includes a TypeScript-powered `nmap` container with a browser UI and CLI mode.

### Files

- `package.json` - Node/TypeScript project metadata
- `tsconfig.json` - TypeScript compiler settings
- `src/index.ts` - scanner CLI
- `Dockerfile` - multi-stage container build with `nmap`
- `compose.yaml` - Docker Desktop-friendly one-command runner
- `.env.example` - sample Docker Compose scan defaults

### Build

```bash
docker build -t david/nmap-scanner:latest .
```

### Run On Docker Desktop

For Docker Desktop on macOS or Windows, the container now starts a web UI by default. Open it in a browser and enter the IP, hostname, or CIDR you want to scan.

Using Docker Compose:

```bash
docker compose up scanner
```

Then open [http://localhost:3000](http://localhost:3000).

Set persistent defaults for Docker Desktop:

```bash
cp .env.example .env
```

Then edit `.env` with the target and ports you want, for example:

```dotenv
NMAP_TARGET=scanme.nmap.org
NMAP_PORTS=22,80,443
NMAP_SCAN_TYPE=connect
NMAP_TIMING=T4
NMAP_UI_PORT=3000
```

After that, start the UI without repeating arguments:

```bash
docker compose up scanner
```

Run the SYN-capable UI profile on a second port when you want elevated scan behavior:

```bash
docker compose --profile syn up scanner-syn
```

That profile opens on [http://localhost:3001](http://localhost:3001) by default and includes `NET_RAW` and `NET_ADMIN`.

If you still want the one-shot CLI behavior, pass scan arguments directly:

```bash
docker run --rm david/nmap-scanner:latest --target scanme.nmap.org --top-ports 20 --service-info --json
```

Launch the browser UI directly with Docker:

```bash
docker run --rm -p 3000:3000 david/nmap-scanner:latest
```

Then open [http://localhost:3000](http://localhost:3000).

If you want direct CLI mode instead of the UI, pass scan arguments:

```bash
docker run --rm david/nmap-scanner:latest --target host.docker.internal --ports 80,443 --json
```

Scan another reachable system by IP or hostname:

```bash
docker run --rm david/nmap-scanner:latest --target scanme.nmap.org --top-ports 20 --service-info --json
```

If your Docker Desktop setup does not resolve `host.docker.internal`, add it explicitly:

```bash
docker run --rm --add-host host.docker.internal:host-gateway david/nmap-scanner:latest --target host.docker.internal --ports 80,443
```

If you need a SYN scan instead of the safer default connect scan, add Linux capabilities:

```bash
docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN david/nmap-scanner:latest --target scanme.nmap.org --scan-type syn --top-ports 20
```

### UI behavior

- The default browser form lets you enter a target IP, hostname, or CIDR.
- Optional controls let you set ports, top ports, timing, scan type, service detection, OS detection, and IPv6.
- Scan output is rendered back into the page after the form submits.

### CLI options

- `--target <host-or-cidr>` scan target, defaulting to `host.docker.internal`
- `--ports <list>` explicit ports or ranges
- `--top-ports <number>` most common ports to scan
- `--timing <T0-T5>` nmap timing template
- `--scan-type <connect|syn>` connect scan by default, SYN when capabilities are available
- `--service-info` enable service/version detection
- `--os-detect` enable OS detection
- `--ipv6` enable IPv6 mode
- `--json` return structured JSON with stdout/stderr
- `--web` start the browser UI explicitly

### Notes

- The container now runs as the non-root `node` user, which fits Docker Desktop better for normal `-sT` scans.
- No-argument container launches now start the web UI instead of a one-shot scan.
- `--scan-type connect` is the default because it works without raw socket privileges.
- `--scan-type syn` and `--os-detect` may still need `--cap-add NET_RAW --cap-add NET_ADMIN`, and results can vary more on Docker Desktop than on native Linux.
- Docker Desktop networking is VM-based, so host discovery and low-level fingerprinting are usually less accurate than on a native Linux host.
- `compose.yaml` publishes the UI on `localhost:3000` by default, and the optional SYN profile publishes on `localhost:3001`.
- The UI uses `host.docker.internal` as the default scan target, and you can override defaults with `NMAP_TARGET`, `NMAP_PORTS`, `NMAP_TOP_PORTS`, `NMAP_SCAN_TYPE`, `NMAP_TIMING`, `NMAP_UI_PORT`, and `NMAP_UI_PORT_SYN`.
- `.env` is ignored by git, so you can keep your local scan defaults without committing them.
