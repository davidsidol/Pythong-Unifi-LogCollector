#!/usr/bin/env python3
"""
UniFi Syslog Collector

Receives syslog from UniFi Network Controller and APs, then stores logs as
JSON-lines files grouped by date and device.
"""

from __future__ import annotations

import argparse
import configparser
import datetime as dt
import json
import logging
import queue
import re
import signal
import socketserver
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


PRI_RE = re.compile(r"^<(\d{1,3})>(.*)$", re.DOTALL)
RFC3164_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>[^\s]+)\s*(?P<rest>.*)$"
)
APP_RE = re.compile(r"^(?P<app>[^\[:]+)(?:\[\d+\])?:\s?(?P<msg>.*)$")

SEVERITY_MAP = {
    0: "emergency",
    1: "alert",
    2: "critical",
    3: "error",
    4: "warning",
    5: "notice",
    6: "informational",
    7: "debug",
}

FACILITY_MAP = {
    0: "kern",
    1: "user",
    2: "mail",
    3: "daemon",
    4: "auth",
    5: "syslog",
    6: "lpr",
    7: "news",
    8: "uucp",
    9: "clock",
    10: "authpriv",
    11: "ftp",
    12: "ntp",
    13: "audit",
    14: "alert",
    15: "clock2",
    16: "local0",
    17: "local1",
    18: "local2",
    19: "local3",
    20: "local4",
    21: "local5",
    22: "local6",
    23: "local7",
}


def sanitize_filename(name: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", name.strip())
    return safe[:128] if safe else "unknown_device"


def parse_rfc3164_timestamp(raw_ts: str) -> Optional[str]:
    year = dt.datetime.utcnow().year
    try:
        parsed = dt.datetime.strptime(f"{year} {raw_ts}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    return parsed.replace(tzinfo=dt.timezone.utc).isoformat()


def parse_syslog(payload: str, source_ip: str) -> dict:
    record = {
        "received_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source_ip": source_ip,
        "hostname": source_ip,
        "facility": None,
        "severity": None,
        "device_timestamp_utc": None,
        "app": None,
        "message": payload,
        "raw": payload,
    }

    msg = payload.strip()
    pri_match = PRI_RE.match(msg)
    if pri_match:
        pri = int(pri_match.group(1))
        msg = pri_match.group(2).lstrip()
        facility_num = pri // 8
        severity_num = pri % 8
        record["facility"] = FACILITY_MAP.get(facility_num, f"facility_{facility_num}")
        record["severity"] = SEVERITY_MAP.get(severity_num, f"severity_{severity_num}")

    rfc3164_match = RFC3164_RE.match(msg)
    if rfc3164_match:
        raw_ts = rfc3164_match.group("ts")
        host = rfc3164_match.group("host")
        rest = rfc3164_match.group("rest")
        record["device_timestamp_utc"] = parse_rfc3164_timestamp(raw_ts)
        record["hostname"] = host
        msg = rest

    app_match = APP_RE.match(msg)
    if app_match:
        record["app"] = app_match.group("app")
        record["message"] = app_match.group("msg")
    else:
        record["message"] = msg

    return record


@dataclass
class CollectorConfig:
    host: str
    port: int
    protocols: tuple[str, ...]
    max_message_size: int
    log_directory: Path
    app_log_level: str
    app_log_file: Optional[Path]

    @staticmethod
    def from_file(path: Path) -> "CollectorConfig":
        parser = configparser.ConfigParser()
        with path.open("r", encoding="utf-8") as fh:
            parser.read_file(fh)

        host = parser.get("listener", "host", fallback="0.0.0.0")
        port = parser.getint("listener", "port", fallback=5514)
        protocols_raw = parser.get("listener", "protocols", fallback="udp")
        protocols = tuple(
            p.strip().lower() for p in protocols_raw.split(",") if p.strip()
        )
        max_message_size = parser.getint("listener", "max_message_size", fallback=65535)

        log_directory = Path(
            parser.get("storage", "log_directory", fallback="./unifi_collected_logs")
        ).expanduser()

        app_log_level = parser.get("application", "log_level", fallback="INFO")
        app_log_file_str = parser.get("application", "log_file", fallback="").strip()
        app_log_file = Path(app_log_file_str) if app_log_file_str else None

        if not protocols:
            raise ValueError("listener.protocols must include at least one protocol.")
        for protocol in protocols:
            if protocol not in {"udp", "tcp"}:
                raise ValueError("listener.protocols must contain only udp and/or tcp.")
        if port <= 0 or port > 65535:
            raise ValueError("listener.port must be 1-65535.")

        return CollectorConfig(
            host=host,
            port=port,
            protocols=protocols,
            max_message_size=max_message_size,
            log_directory=log_directory,
            app_log_level=app_log_level.upper(),
            app_log_file=app_log_file,
        )


class LogWriter(threading.Thread):
    def __init__(self, out_dir: Path, q: "queue.Queue[dict]") -> None:
        super().__init__(daemon=True)
        self.out_dir = out_dir
        self.q = q
        self.stop_event = threading.Event()
        self._handles: dict[Path, object] = {}

    def stop(self) -> None:
        self.stop_event.set()

    def _path_for_record(self, record: dict) -> Path:
        date_part = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
        device = sanitize_filename(record.get("hostname") or record.get("source_ip") or "unknown")
        return self.out_dir / date_part / f"{device}.jsonl"

    def _get_handle(self, path: Path):
        handle = self._handles.get(path)
        if handle:
            return handle
        path.parent.mkdir(parents=True, exist_ok=True)
        handle = path.open("a", encoding="utf-8")
        self._handles[path] = handle
        return handle

    def _close_all(self) -> None:
        for handle in self._handles.values():
            try:
                handle.close()
            except OSError:
                pass
        self._handles.clear()

    def run(self) -> None:
        while not self.stop_event.is_set() or not self.q.empty():
            try:
                record = self.q.get(timeout=0.5)
            except queue.Empty:
                continue

            out_path = self._path_for_record(record)
            handle = self._get_handle(out_path)
            handle.write(json.dumps(record, ensure_ascii=True) + "\n")
            handle.flush()
            self.q.task_done()

        self._close_all()


class QueueingUDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = self.request[0]
        server: "SyslogUDPServer" = self.server  # type: ignore[assignment]
        payload = data[: server.max_message_size].decode("utf-8", errors="replace")
        record = parse_syslog(payload, self.client_address[0])
        server.log_queue.put(record)


class QueueingTCPHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        server: "SyslogTCPServer" = self.server  # type: ignore[assignment]
        while True:
            line = self.rfile.readline(server.max_message_size)
            if not line:
                break
            payload = line.decode("utf-8", errors="replace").strip()
            if not payload:
                continue
            record = parse_syslog(payload, self.client_address[0])
            server.log_queue.put(record)


class SyslogUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True

    def __init__(self, addr, handler, log_queue, max_message_size):
        super().__init__(addr, handler)
        self.log_queue = log_queue
        self.max_message_size = max_message_size


class SyslogTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self, addr, handler, log_queue, max_message_size):
        super().__init__(addr, handler)
        self.log_queue = log_queue
        self.max_message_size = max_message_size


def configure_app_logging(level: str, log_file: Optional[Path]) -> None:
    handlers = [logging.StreamHandler()]
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))

    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=handlers,
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Collect UniFi syslog to JSONL files.")
    parser.add_argument(
        "-c",
        "--config",
        default="config.ini",
        help="Path to configuration file (default: config.ini).",
    )
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    config = CollectorConfig.from_file(Path(args.config))
    configure_app_logging(config.app_log_level, config.app_log_file)

    log_queue: "queue.Queue[dict]" = queue.Queue(maxsize=50000)
    writer = LogWriter(config.log_directory, log_queue)
    writer.start()

    servers: list[socketserver.BaseServer] = []
    server_threads: list[threading.Thread] = []

    for protocol in config.protocols:
        if protocol == "udp":
            server = SyslogUDPServer(
                (config.host, config.port),
                QueueingUDPHandler,
                log_queue=log_queue,
                max_message_size=config.max_message_size,
            )
        else:
            server = SyslogTCPServer(
                (config.host, config.port),
                QueueingTCPHandler,
                log_queue=log_queue,
                max_message_size=config.max_message_size,
            )

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append(server)
        server_threads.append(thread)
        logging.info("Listening for %s syslog on %s:%s", protocol.upper(), config.host, config.port)

    stop_event = threading.Event()

    def shutdown_handler(signum, _frame):
        logging.info("Received signal %s, shutting down.", signum)
        stop_event.set()

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    try:
        while not stop_event.is_set():
            stop_event.wait(1.0)
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in server_threads:
            thread.join(timeout=3)

        writer.stop()
        writer.join(timeout=5)
        logging.info("Shutdown complete.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
