# simple_bug_bounty_script

A simple bug bounty tool for lab settings that checks basic localhost exposure and security signals. It is designed for learning and controlled testing, not internet-wide scanning.

## What This Is

This project is a lightweight Python script that:
- Finds simple subdomains for a target base domain.
- Scans common TCP ports on discovered hosts.
- Runs basic vulnerability-oriented checks.
- Writes results to a JSON report.

Default usage is centered on `localhost` so you can test safely in a local lab environment.

## Subdomain Finder: How It Works

The script uses a wordlist-based approach:
- It starts from a base domain (default: `localhost`).
- It creates candidate names such as:
  - `www.localhost`
  - `api.localhost`
  - `dev.localhost`
  - `test.localhost`
  - `staging.localhost`
  - `admin.localhost`
- It attempts DNS resolution for each candidate using `socket.gethostbyname`.
- Any host that resolves is kept for the next stage.

This is intentionally simple and suitable for local/lab demonstration.

## Port Finder: How It Works

For each discovered host, the script scans a predefined set of common ports:
- `21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 6379, 8080`

Implementation details:
- Uses TCP connect checks (`socket.connect_ex`) with short timeouts.
- If connection succeeds, that port is marked open.
- Open ports are listed per host in terminal output and in `scan_report.json`.

## How Subdomain + Port Scanning Work In Tandem

The flow is:
1. Resolve candidate subdomains.
2. For each resolved host, scan common ports.
3. Run basic checks on open ports (for example, flagging risky services).
4. Save combined results in one structured JSON report.

This creates a simple chain: `Discovery -> Enumeration -> Basic Findings`.

## How To Use (Step-by-Step)

- Open PowerShell and go to the project folder:
  ```powershell
  cd d:\coding\simple_bug_bounty_script
  ```
- Run a one-time test scan (recommended first run):
  ```powershell
  python .\simple_bug_bounty_script.py --once --domain localhost
  ```
- Check that the report file was created:
  ```powershell
  Get-Item .\scan_report.json
  ```
- View the report content:
  ```powershell
  Get-Content .\scan_report.json
  ```
- Run continuously every 24 hours:
  ```powershell
  python .\simple_bug_bounty_script.py --domain localhost --interval-hours 24
  ```
- Stop continuous mode with `Ctrl+C`.

Optional local test:
- Start a local HTTP server:
  ```powershell
  python -m http.server 8080
  ```
- Run the scan again and confirm `8080` appears in open ports.

## What To Look For In Output

In terminal and JSON output, focus on:
- `host`: Which resolved host was tested.
- `open_ports`: Which services are reachable.
- `findings`: Basic risk notes, such as:
  - insecure or sensitive service ports open (example: `23`, `445`, `6379`)
  - missing basic HTTP headers
  - potentially old banner hints

If a host has many open management/service ports, treat it as a priority for hardening in your lab.

## Use Case Scenario

You are building a vulnerable lab on your own machine and want a repeatable daily check.  
Run this script against `localhost` to quickly see:
- what subdomain labels resolve,
- what services are exposed,
- and whether basic risky patterns appear.

This helps you verify security posture changes over time after configuration updates.
