import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { spawn } from "node:child_process";
import { URLSearchParams } from "node:url";

const DEFAULT_TARGET = "host.docker.internal";
const DEFAULT_PORT = Number.parseInt(process.env.PORT ?? "3000", 10);

type Timing = "T0" | "T1" | "T2" | "T3" | "T4" | "T5";
type ScanType = "connect" | "syn";

type ScanOptions = {
  target: string;
  ports?: string;
  topPorts?: number;
  timing: Timing;
  scanType: ScanType;
  serviceInfo: boolean;
  osDetect: boolean;
  ipv6: boolean;
};

type ParsedArgs = {
  options: ScanOptions;
  json: boolean;
};

type ScanResult = {
  stdout: string;
  stderr: string;
  exitCode: number | null;
};

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#39;");
}

function printUsage(): void {
  console.log(`Usage:
  node dist/index.js [options]
  node dist/index.js --web

Options:
  --target <value>       Single host, hostname, or CIDR target to scan (default: ${DEFAULT_TARGET})
  --ports <list>         Port list/range, for example 22,80,443 or 1-1024
  --top-ports <number>   Scan the top N most common ports
  --timing <T0-T5>       Nmap timing template (default: T3)
  --scan-type <type>     connect or syn (default: connect)
  --service-info         Enable service/version detection (-sV)
  --os-detect            Enable OS detection (-O)
  --ipv6                 Enable IPv6 scanning (-6)
  --json                 Wrap the scan output in JSON
  --web                  Start the browser UI on port ${DEFAULT_PORT}
  --help                 Show this help

Docker Desktop example:
  docker build -t david/nmap-scanner:latest .
  docker run --rm -p 3000:3000 david/nmap-scanner:latest
`);
}

function fail(message: string): never {
  console.error(`Error: ${message}`);
  process.exit(1);
}

function readNextValue(args: string[], index: number, flag: string): string {
  const value = args[index + 1];
  if (!value || value.startsWith("--")) {
    fail(`Missing value for ${flag}`);
  }
  return value;
}

function parsePositiveInteger(value: string, flag: string): number {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    fail(`${flag} must be a positive integer`);
  }
  return parsed;
}

function validateTarget(target: string): string {
  const trimmed = target.trim();
  if (!trimmed) {
    throw new Error("Target is required");
  }

  if (!/^[a-zA-Z0-9:/._-]+$/.test(trimmed)) {
    throw new Error("Target contains unsupported characters");
  }

  return trimmed;
}

function validatePorts(ports: string): string {
  const trimmed = ports.trim();
  if (!trimmed) {
    throw new Error("Ports cannot be empty");
  }

  if (!/^[0-9,\-]+$/.test(trimmed)) {
    throw new Error("Ports must contain only digits, commas, and dashes");
  }

  return trimmed;
}

function parseOptionsFromValues(values: Record<string, string | undefined>): ScanOptions {
  const timing = (values.timing ?? "T3").toUpperCase();
  if (!/^T[0-5]$/.test(timing)) {
    throw new Error("Timing must be one of T0, T1, T2, T3, T4, or T5");
  }

  const scanType = (values.scanType ?? "connect").toLowerCase();
  if (scanType !== "connect" && scanType !== "syn") {
    throw new Error("Scan type must be either connect or syn");
  }

  const ports = values.ports?.trim();
  const topPorts = values.topPorts?.trim();

  if (ports && topPorts) {
    throw new Error("Use either ports or top ports, not both");
  }

  return {
    target: validateTarget(values.target ?? process.env.NMAP_TARGET ?? DEFAULT_TARGET),
    ports: ports ? validatePorts(ports) : undefined,
    topPorts: topPorts ? parsePositiveInteger(topPorts, "top ports") : undefined,
    timing: timing as Timing,
    scanType,
    serviceInfo: values.serviceInfo === "true",
    osDetect: values.osDetect === "true",
    ipv6: values.ipv6 === "true"
  };
}

function parseArgs(argv: string[]): ParsedArgs {
  const values: Record<string, string | undefined> = {
    target: process.env.NMAP_TARGET ?? DEFAULT_TARGET,
    timing: "T3",
    scanType: "connect",
    serviceInfo: "false",
    osDetect: "false",
    ipv6: "false"
  };

  let json = false;

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];

    switch (arg) {
      case "--target":
        values.target = readNextValue(argv, index, arg);
        index += 1;
        break;
      case "--ports":
        values.ports = readNextValue(argv, index, arg);
        index += 1;
        break;
      case "--top-ports":
        values.topPorts = readNextValue(argv, index, arg);
        index += 1;
        break;
      case "--timing":
        values.timing = readNextValue(argv, index, arg);
        index += 1;
        break;
      case "--scan-type":
        values.scanType = readNextValue(argv, index, arg);
        index += 1;
        break;
      case "--service-info":
        values.serviceInfo = "true";
        break;
      case "--os-detect":
        values.osDetect = "true";
        break;
      case "--ipv6":
        values.ipv6 = "true";
        break;
      case "--json":
        json = true;
        break;
      case "--help":
        printUsage();
        process.exit(0);
      default:
        fail(`Unknown argument: ${arg}`);
    }
  }

  return {
    options: parseOptionsFromValues(values),
    json
  };
}

function buildNmapArgs(options: ScanOptions): string[] {
  const args: string[] = ["-Pn", `-${options.timing}`];

  if (options.scanType === "connect") {
    args.push("-sT");
  } else {
    args.push("-sS");
  }

  if (options.ipv6) {
    args.push("-6");
  }

  if (options.ports) {
    args.push("-p", options.ports);
  } else if (options.topPorts) {
    args.push("--top-ports", String(options.topPorts));
  }

  if (options.serviceInfo) {
    args.push("-sV");
  }

  if (options.osDetect) {
    args.push("-O");
  }

  args.push(options.target);
  return args;
}

function runNmap(args: string[]): Promise<ScanResult> {
  return new Promise((resolve, reject) => {
    const child = spawn("nmap", args, { stdio: ["ignore", "pipe", "pipe"] });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });

    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });

    child.on("error", (error) => {
      reject(error);
    });

    child.on("close", (exitCode) => {
      resolve({ stdout, stderr, exitCode });
    });
  });
}

function checkbox(name: string, checked: boolean, label: string): string {
  return `<label class="check"><input type="checkbox" name="${name}" value="true" ${checked ? "checked" : ""}> ${label}</label>`;
}

function renderPage(options: ScanOptions, result?: ScanResult, error?: string): string {
  const combinedOutput = [result?.stdout.trim(), result?.stderr.trim()].filter(Boolean).join("\n\n");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Nmap Scanner</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f3efe5;
      --panel: rgba(255, 251, 244, 0.88);
      --ink: #1a2533;
      --muted: #546273;
      --line: rgba(26, 37, 51, 0.14);
      --accent: #ba4a00;
      --accent-strong: #8d3600;
      --good: #0d6b48;
      --bad: #a42828;
      --shadow: 0 24px 60px rgba(62, 40, 18, 0.18);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: "Iowan Old Style", "Palatino Linotype", "Book Antiqua", serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(186, 74, 0, 0.20), transparent 30%),
        radial-gradient(circle at bottom right, rgba(13, 107, 72, 0.16), transparent 28%),
        linear-gradient(135deg, #ece3d0 0%, #f7f4ed 50%, #efe6d9 100%);
      padding: 32px 16px;
    }
    .shell {
      width: min(980px, 100%);
      margin: 0 auto;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 28px;
      box-shadow: var(--shadow);
      overflow: hidden;
      backdrop-filter: blur(10px);
    }
    .hero {
      padding: 28px 28px 18px;
      border-bottom: 1px solid var(--line);
      background:
        linear-gradient(135deg, rgba(255,255,255,0.45), rgba(255,255,255,0.1)),
        linear-gradient(120deg, rgba(186, 74, 0, 0.08), rgba(13, 107, 72, 0.08));
    }
    .eyebrow {
      margin: 0 0 6px;
      font-size: 0.82rem;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: var(--accent);
      font-weight: 700;
    }
    h1 {
      margin: 0;
      font-size: clamp(2rem, 4vw, 3.4rem);
      line-height: 0.95;
      font-weight: 700;
    }
    .sub {
      max-width: 56ch;
      margin: 14px 0 0;
      color: var(--muted);
      font-size: 1rem;
      line-height: 1.5;
    }
    .content {
      display: grid;
      grid-template-columns: 1.2fr 0.8fr;
      gap: 0;
    }
    .pane {
      padding: 24px 28px 28px;
    }
    .pane + .pane {
      border-left: 1px solid var(--line);
    }
    form {
      display: grid;
      gap: 18px;
    }
    .field-grid {
      display: grid;
      gap: 14px;
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
    .field, .field-wide {
      display: grid;
      gap: 8px;
    }
    .field-wide {
      grid-column: 1 / -1;
    }
    label.text {
      font-size: 0.82rem;
      font-weight: 700;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      color: var(--muted);
    }
    input[type="text"], input[type="number"], select {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 16px;
      background: rgba(255,255,255,0.76);
      padding: 14px 16px;
      font: inherit;
      color: var(--ink);
      outline: none;
    }
    input:focus, select:focus {
      border-color: rgba(186, 74, 0, 0.45);
      box-shadow: 0 0 0 4px rgba(186, 74, 0, 0.12);
    }
    .checks {
      display: grid;
      gap: 10px;
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
    .check {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 12px 14px;
      border-radius: 16px;
      border: 1px solid var(--line);
      background: rgba(255,255,255,0.6);
      color: var(--ink);
      font-size: 0.96rem;
    }
    .check input {
      inline-size: 16px;
      block-size: 16px;
      accent-color: var(--accent);
    }
    .actions {
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
    }
    button {
      border: 0;
      border-radius: 999px;
      padding: 14px 22px;
      font: inherit;
      font-weight: 700;
      color: #fff9f4;
      background: linear-gradient(135deg, var(--accent), var(--accent-strong));
      cursor: pointer;
      box-shadow: 0 12px 24px rgba(186, 74, 0, 0.22);
    }
    .tip {
      font-size: 0.92rem;
      color: var(--muted);
    }
    .callout {
      margin-bottom: 16px;
      border-radius: 18px;
      padding: 14px 16px;
      font-size: 0.95rem;
      line-height: 1.5;
      border: 1px solid var(--line);
    }
    .error {
      background: rgba(164, 40, 40, 0.08);
      color: var(--bad);
      border-color: rgba(164, 40, 40, 0.2);
    }
    .status {
      background: rgba(13, 107, 72, 0.07);
      color: var(--good);
      border-color: rgba(13, 107, 72, 0.2);
    }
    .meta {
      display: grid;
      gap: 12px;
    }
    .card {
      border: 1px solid var(--line);
      border-radius: 20px;
      padding: 16px;
      background: rgba(255,255,255,0.58);
    }
    .card h2 {
      margin: 0 0 8px;
      font-size: 1rem;
    }
    .card p, .card li {
      margin: 0;
      color: var(--muted);
      line-height: 1.5;
      font-size: 0.96rem;
    }
    .card ul {
      margin: 0;
      padding-left: 18px;
    }
    pre {
      margin: 0;
      padding: 18px;
      border-radius: 20px;
      background: #1a2533;
      color: #eef4f7;
      overflow: auto;
      font-family: "SFMono-Regular", "Cascadia Code", "Menlo", monospace;
      font-size: 0.92rem;
      line-height: 1.5;
      min-height: 280px;
      white-space: pre-wrap;
      word-break: break-word;
    }
    @media (max-width: 860px) {
      .content {
        grid-template-columns: 1fr;
      }
      .pane + .pane {
        border-left: 0;
        border-top: 1px solid var(--line);
      }
      .field-grid, .checks {
        grid-template-columns: 1fr;
      }
    }
  </style>
</head>
<body>
  <main class="shell">
    <section class="hero">
      <p class="eyebrow">Docker Desktop UI</p>
      <h1>Containerized Nmap Scanner</h1>
      <p class="sub">Enter an IP address, hostname, or CIDR range and launch a scan from the browser. The container runs <code>nmap</code> locally and streams the result back into this page.</p>
    </section>
    <section class="content">
      <section class="pane">
        ${error ? `<div class="callout error">${escapeHtml(error)}</div>` : ""}
        ${result ? `<div class="callout status">Scan finished with exit code <strong>${String(result.exitCode ?? 1)}</strong>.</div>` : ""}
        <form method="post" action="/scan">
          <div class="field-grid">
            <div class="field-wide">
              <label class="text" for="target">Target IP, Hostname, or CIDR</label>
              <input id="target" name="target" type="text" value="${escapeHtml(options.target)}" placeholder="192.168.1.10 or scanme.nmap.org" required>
            </div>
            <div class="field">
              <label class="text" for="ports">Ports</label>
              <input id="ports" name="ports" type="text" value="${escapeHtml(options.ports ?? "")}" placeholder="80,443">
            </div>
            <div class="field">
              <label class="text" for="topPorts">Top Ports</label>
              <input id="topPorts" name="topPorts" type="number" min="1" value="${escapeHtml(options.topPorts ? String(options.topPorts) : "")}" placeholder="20">
            </div>
            <div class="field">
              <label class="text" for="timing">Timing</label>
              <select id="timing" name="timing">
                ${["T0", "T1", "T2", "T3", "T4", "T5"].map((value) => `<option value="${value}" ${options.timing === value ? "selected" : ""}>${value}</option>`).join("")}
              </select>
            </div>
            <div class="field">
              <label class="text" for="scanType">Scan Type</label>
              <select id="scanType" name="scanType">
                <option value="connect" ${options.scanType === "connect" ? "selected" : ""}>Connect (-sT)</option>
                <option value="syn" ${options.scanType === "syn" ? "selected" : ""}>SYN (-sS)</option>
              </select>
            </div>
          </div>
          <div class="checks">
            ${checkbox("serviceInfo", options.serviceInfo, "Service detection")}
            ${checkbox("osDetect", options.osDetect, "OS detection")}
            ${checkbox("ipv6", options.ipv6, "IPv6")}
          </div>
          <div class="actions">
            <button type="submit">Run Scan</button>
            <span class="tip">Default target: ${escapeHtml(DEFAULT_TARGET)}. Leave ports empty to let nmap choose its defaults.</span>
          </div>
        </form>
      </section>
      <aside class="pane meta">
        <section class="card">
          <h2>How to open it</h2>
          <p>Run the container with port <code>3000</code> published, then open <code>http://localhost:3000</code> in your browser.</p>
        </section>
        <section class="card">
          <h2>Tips</h2>
          <ul>
            <li>Use either explicit ports or top ports, not both.</li>
            <li>Connect scans work best on Docker Desktop without extra privileges.</li>
            <li>SYN and OS detection may need additional Linux capabilities.</li>
          </ul>
        </section>
        <section class="card">
          <h2>Last Output</h2>
          <pre>${escapeHtml(combinedOutput || "No scan has been run yet.")}</pre>
        </section>
      </aside>
    </section>
  </main>
</body>
</html>`;
}

function sendHtml(response: ServerResponse, statusCode: number, body: string): void {
  response.writeHead(statusCode, { "content-type": "text/html; charset=utf-8" });
  response.end(body);
}

function readRequestBody(request: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = "";

    request.on("data", (chunk: Buffer) => {
      body += chunk.toString("utf8");

      if (body.length > 25_000) {
        reject(new Error("Request body is too large"));
        request.destroy();
      }
    });

    request.on("end", () => resolve(body));
    request.on("error", reject);
  });
}

async function startWebServer(): Promise<void> {
  const defaultOptions = parseOptionsFromValues({
    target: process.env.NMAP_TARGET ?? DEFAULT_TARGET,
    scanType: process.env.NMAP_SCAN_TYPE ?? "connect",
    timing: process.env.NMAP_TIMING ?? "T3",
    ports: process.env.NMAP_PORTS,
    topPorts: process.env.NMAP_TOP_PORTS,
    serviceInfo: process.env.NMAP_SERVICE_INFO ?? "false",
    osDetect: process.env.NMAP_OS_DETECT ?? "false",
    ipv6: process.env.NMAP_IPV6 ?? "false"
  });

  const server = createServer(async (request, response) => {
    if (request.method === "GET" && request.url === "/") {
      sendHtml(response, 200, renderPage(defaultOptions));
      return;
    }

    if (request.method === "POST" && request.url === "/scan") {
      try {
        const body = await readRequestBody(request);
        const params = new URLSearchParams(body);
        const options = parseOptionsFromValues({
          target: params.get("target") ?? undefined,
          ports: params.get("ports") ?? undefined,
          topPorts: params.get("topPorts") ?? undefined,
          timing: params.get("timing") ?? undefined,
          scanType: params.get("scanType") ?? undefined,
          serviceInfo: params.get("serviceInfo") === "true" ? "true" : "false",
          osDetect: params.get("osDetect") === "true" ? "true" : "false",
          ipv6: params.get("ipv6") === "true" ? "true" : "false"
        });
        const result = await runNmap(buildNmapArgs(options));
        sendHtml(response, 200, renderPage(options, result));
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        sendHtml(response, 400, renderPage(defaultOptions, undefined, message));
      }
      return;
    }

    response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    response.end("Not found");
  });

  server.listen(DEFAULT_PORT, "0.0.0.0", () => {
    console.log(`Nmap UI available at http://0.0.0.0:${DEFAULT_PORT}`);
  });
}

async function runCli(argv: string[]): Promise<void> {
  const { options, json } = parseArgs(argv);
  const nmapArgs = buildNmapArgs(options);
  const result = await runNmap(nmapArgs);

  if (json) {
    console.log(JSON.stringify({
      command: ["nmap", ...nmapArgs],
      exitCode: result.exitCode,
      stdout: result.stdout.trim(),
      stderr: result.stderr.trim()
    }, null, 2));
  } else {
    if (result.stdout.trim()) {
      process.stdout.write(result.stdout);
    }

    if (result.stderr.trim()) {
      process.stderr.write(result.stderr);
    }
  }

  if (result.exitCode !== 0) {
    process.exit(result.exitCode ?? 1);
  }
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);

  if (argv.length === 0 || argv.includes("--web")) {
    await startWebServer();
    return;
  }

  await runCli(argv);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`Failed to run nmap: ${message}`);
  process.exit(1);
});
