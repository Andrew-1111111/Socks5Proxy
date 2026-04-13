# Socks5Proxy

**English** | [Русский](README.ru.md)

A high-performance SOCKS5 proxy in C#/.NET 9 with outbound traffic binding to a chosen interface, built-in DNS resolution, and detailed logging.

## Important: project origin

This repository is a heavily reworked fork of the original [RickyLin/SimpleSocks5Proxy](https://github.com/RickyLin/SimpleSocks5Proxy).

## Features

- Full baseline SOCKS5 (RFC 1928) support for `CONNECT` and `UDP ASSOCIATE`.
- Support for `IPv4`, `IPv6`, and domain names.
- Asynchronous architecture handling many concurrent connections.
- Limit on simultaneous connections (`MaxConnections`); `0` means unlimited.
- Bind outbound TCP/UDP to a specific local IP (`OutputIPAddress`).
- Resolve hostnames via a configurable DNS server (`DnsServer`) with caching.
- UDP relay with client validation, source filtering, and idle timeout.
- Friendly names for IPs in logs (`IPAddressMappings`) for easier troubleshooting.
- Single-instance guard to prevent a second copy from running.
- Clean shutdown on `Ctrl+C` and proper resource cleanup.
- Structured logging via Serilog.

## Protocol support

### Supported

- SOCKS5 version `0x05`
- Authentication method `No Authentication` (`0x00`)
- Authentication method `Username/Password` (`0x02`)
- Command `CONNECT` (TCP)
- Command `UDP ASSOCIATE` (UDP relay)
- IPv4, IPv6, and domain addresses

### Not supported

- GSSAPI authentication for SOCKS5
- BIND command

## Requirements

- .NET 9 SDK / runtime
- Windows / Linux / macOS
- Administrator / root privileges (the app checks this at startup and may relaunch with elevation; elevated rights are needed for binding to ports 1–1024)

## Quick start

### 1) Build

```bash
dotnet build Socks5Proxy.sln -c Release
```

### 2) Configure `proxy.json`

The file lives at `Socks5Proxy/proxy.json`.

Example:

```json
{
  "ListenIPAddress": "0.0.0.0",
  "ListenPort": 1080,
  "OutputIPAddress": [],
  "OutputInterfaceName": [
    "tap1",
    "tun2"
  ],
  "DnsServer": "8.8.8.8",
  "MaxConnections": 1000,
  "RunDelayS": 0,
  "Username": "",
  "Password": "",
  "IPAddressMappings": [
    {
      "IPAddress": "192.168.0.10",
      "FriendlyName": "PC_1"
    }
  ]
}
```

### 3) Run

From the repository root:

```bash
dotnet run --project Socks5Proxy
```

Or with an explicit config path:

```bash
dotnet run --project Socks5Proxy -- --config "D:\path\to\proxy.json"
```

## Configuration

- `ListenIPAddress` — IP address the SOCKS5 server listens on (e.g. `127.0.0.1` or `0.0.0.0`).
- `ListenPort` — TCP listen port (range: 0–65535). If port 0 is selected, the system will automatically select a random port.
- `OutputIPAddress` — list of local interface IPs for outbound connections. The app picks the first available working address. May be `null`.
- `OutputInterfaceName` — list of network interface names for outbound connections. The app picks the first available working interface. Takes precedence over `OutputIPAddress`. May be `null`.
- `DnsServer` — DNS server IP for resolving domain names. May be `null`.
- `MaxConnections` — maximum concurrent connections. `0` means no limit.
- `RunDelayS` — startup delay in seconds. `0` means no delay.
- `IPAddressMappings` — array of IP-to-friendly-name mappings for logging.
- `Username` — SOCKS5 username. Leave unused for `No Authentication`. May be `null`.
- `Password` — SOCKS5 password. Leave unused for `No Authentication`. May be `null`.

## Logging

- Configured in `Socks5Proxy/appsettings.json` (Serilog).
- Defaults to console output.
- Friendly mappings add a suffix like `(MyHost)` to IPs/endpoints in log messages.

## Security and operations

- Handshake/request timeouts to mitigate slow-client issues.
- UDP relay source control to reduce open-proxy abuse risk.
- Connection limits and orderly teardown of active work on shutdown.
- If `proxy.json` is missing, the app exits with a clear error and a hint about `--config`.

## License and attribution

This project is distributed as a fork of the original [RickyLin/SimpleSocks5Proxy](https://github.com/RickyLin/SimpleSocks5Proxy).
