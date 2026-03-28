import { spawn } from "node:child_process";

type ScanOptions = {
  target: string;
  ports?: string;
  topPorts?: number;
  timing: "T0" | "T1" | "T2" | "T3" | "T4" | "T5";
  serviceInfo: boolean;
  osDetect: boolean;
  ipv6: boolean;
};

type ParsedArgs = {
  options: ScanOptions;
  json: boolean;
};

function printUsage(): void {
  console.log(`Usage:
  node dist/index.js --target <host-or-cidr> [options]

Options:
  --target <value>       Single host, hostname, or CIDR target to scan
  --ports <list>         Port list/range, for example 22,80,443 or 1-1024
  --top-ports <number>   Scan the top N most common ports
  --timing <T0-T5>       Nmap timing template (default: T3)
  --service-info         Enable service/version detection (-sV)
  --os-detect            Enable OS detection (-O)
  --ipv6                 Enable IPv6 scanning (-6)
  --json                 Wrap the scan output in JSON
  --help                 Show this help

Container example:
  docker build -t ts-nmap-scanner .
  docker run --rm --network host ts-nmap-scanner --target scanme.nmap.org --top-ports 20 --service-info --json
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

function parseArgs(argv: string[]): ParsedArgs {
  const options: ScanOptions = {
    target: "",
    timing: "T3",
    serviceInfo: false,
    osDetect: false,
    ipv6: false
  };

  let json = false;

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];

    switch (arg) {
      case "--target":
        options.target = readNextValue(argv, index, arg);
        index += 1;
        break;
      case "--ports":
        options.ports = readNextValue(argv, index, arg);
        index += 1;
        break;
      case "--top-ports":
        options.topPorts = parsePositiveInteger(readNextValue(argv, index, arg), arg);
        index += 1;
        break;
      case "--timing": {
        const timing = readNextValue(argv, index, arg).toUpperCase();
        if (!/^T[0-5]$/.test(timing)) {
          fail("--timing must be one of T0, T1, T2, T3, T4, or T5");
        }
        options.timing = timing as ScanOptions["timing"];
        index += 1;
        break;
      }
      case "--service-info":
        options.serviceInfo = true;
        break;
      case "--os-detect":
        options.osDetect = true;
        break;
      case "--ipv6":
        options.ipv6 = true;
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

  if (!options.target) {
    fail("--target is required");
  }

  if (options.ports && options.topPorts) {
    fail("Use either --ports or --top-ports, not both");
  }

  return { options, json };
}

function buildNmapArgs(options: ScanOptions): string[] {
  const args: string[] = ["-Pn", `-${options.timing}`];

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

function runNmap(args: string[]): Promise<{ stdout: string; stderr: string; exitCode: number | null }> {
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

async function main(): Promise<void> {
  const { options, json } = parseArgs(process.argv.slice(2));
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

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`Failed to run nmap: ${message}`);
  process.exit(1);
});
