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

This repo now also includes a small TypeScript CLI that runs `nmap` inside a container.

### Files

- `package.json` - Node/TypeScript project metadata
- `tsconfig.json` - TypeScript compiler settings
- `src/index.ts` - scanner CLI
- `Dockerfile` - multi-stage container build with `nmap`

### Build

```bash
docker build -t ts-nmap-scanner .
```

### Run

Host networking gives the container the clearest path for network scans on Linux:

```bash
docker run --rm --network host ts-nmap-scanner --target scanme.nmap.org --top-ports 20 --service-info --json
```

If you prefer a specific port range:

```bash
docker run --rm --network host ts-nmap-scanner --target 192.168.1.0/24 --ports 22,80,443
```

### CLI options

- `--target <host-or-cidr>` required scan target
- `--ports <list>` explicit ports or ranges
- `--top-ports <number>` most common ports to scan
- `--timing <T0-T5>` nmap timing template
- `--service-info` enable service/version detection
- `--os-detect` enable OS detection
- `--ipv6` enable IPv6 mode
- `--json` return structured JSON with stdout/stderr

### Notes

- Some scan types and OS detection may require elevated container privileges depending on your host environment.
- Docker Desktop on macOS/Windows handles networking differently than Linux, so `--network host` may not behave the same way.
