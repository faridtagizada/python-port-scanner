# python-port-scanner

A small multi-threaded TCP connect port scanner written in Python. It finds open ports, names the service, can grab banners, and prints a table or writes JSON or CSV.

Only scan machines you own or have written permission to scan. Scanning without permission can be illegal. `127.0.0.1` or `scanme.nmap.org` are fine for trying it out.

## What it does

- Fast parallel scanning with `socket` and `ThreadPoolExecutor`
- Port specs: a single port (`22`), a list (`22,80`), a range (`1-1024`) or `common`
- Service name lookup for well-known ports
- Banner grabbing with `-b`, sending a `HEAD` request on HTTP ports
- Hostnames are resolved to an IP first
- Output as a terminal table, JSON or CSV

## Install

```bash
git clone https://github.com/<your-username>/python-port-scanner.git
cd python-port-scanner
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Needs Python 3.8+. The scanner has no dependencies; `requirements.txt` is only for `pytest`.

## Usage

```bash
# default scan (ports 1-1024)
python -m portscanner 127.0.0.1

# the most common ports, with banners
python -m portscanner scanme.nmap.org -p common -b

# specific ports, JSON output
python -m portscanner 192.168.1.1 -p 22,80,443 -o results/scan.json

# every port, 200 threads, short timeout
python -m portscanner 127.0.0.1 -p 1-65535 -t 200 --timeout 0.5
```

| Option | Description | Default |
|---|---|---|
| `-p, --ports` | Ports to scan | `1-1024` |
| `-t, --threads` | Number of threads | `100` |
| `--timeout` | Timeout in seconds | `1.0` |
| `-b, --banner` | Grab banners | off |
| `-o, --output` | `.json` or `.csv` file | none |

Example (against two test listeners on 127.0.0.1):

```
$ python -m portscanner 127.0.0.1 -b
[*] Target: 127.0.0.1 (127.0.0.1) | 1024 ports | 2026-10-26 07:19:20
PORT    STATE   SERVICE         BANNER
------------------------------------------------------------
22      open    ssh             SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13
80      open    http            HTTP/1.0 200 OK

[+] Open ports: 2, time: 0.05s
```

## How it works

For every port the scanner tries a normal TCP three-way handshake (`connect_ex`). If the connection succeeds, the port counts as open. A thread pool checks many ports at the same time.

## Layout

```
python-port-scanner/
├── portscanner/
│   ├── scanner.py    # scanning logic
│   ├── services.py   # port -> service name
│   └── cli.py        # argparse CLI
├── tests/test_scanner.py
├── requirements.txt
└── README.md
```

## Tests

```bash
pytest -v
```

## TODO

- UDP scanning
- host discovery over a CIDR range (e.g. `192.168.1.0/24`)
- SYN scan (with `scapy`)
- HTML report

## License

MIT
