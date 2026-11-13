import json
import socket
import threading

import pytest

from portscanner.cli import main
from portscanner.scanner import parse_ports, scan, scan_port


def test_parse_single_and_list():
    assert parse_ports("22,80") == [22, 80]


def test_parse_range():
    assert parse_ports("20-23") == [20, 21, 22, 23]


def test_parse_mixed_dedup():
    assert parse_ports("22,20-23") == [20, 21, 22, 23]


def test_parse_common():
    ports = parse_ports("common")
    assert 22 in ports and 443 in ports


@pytest.mark.parametrize("bad", ["0", "70000", "30-20", "abc", "-5", "1-", "²"])
def test_parse_invalid(bad):
    with pytest.raises(ValueError):
        parse_ports(bad)


def test_huge_range_is_rejected_before_expanding():
    # used to build a list of a billion ports before checking them
    with pytest.raises(ValueError, match="between 1 and 65535"):
        parse_ports("1-999999999")


@pytest.mark.parametrize("args", [["-t", "0"], ["-t", "-3"], ["--timeout", "0"], ["--timeout", "-1"],
                                  ["--timeout", "nan"], ["--timeout", "abc"]])
def test_cli_rejects_bad_numbers(args):
    # --timeout 0 used to report every open port as closed, the others crashed
    with pytest.raises(SystemExit) as exc:
        main(["127.0.0.1", "-p", "1"] + args)
    assert exc.value.code == 2


def test_output_folder_is_created(server, tmp_path):
    # the README example "-o results/scan.json" crashed after the scan
    out = tmp_path / "results" / "scan.json"
    assert main(["127.0.0.1", "-p", str(server), "--timeout", "0.5", "-o", str(out)]) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert [r["port"] for r in data["results"]] == [server]


def test_csv_extension_is_case_insensitive(server, tmp_path):
    out = tmp_path / "scan.CSV"
    assert main(["127.0.0.1", "-p", str(server), "--timeout", "0.5", "-o", str(out)]) == 0
    assert out.read_text(encoding="utf-8").startswith("port,state,service,banner")


@pytest.fixture
def server():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]

    def run():
        while True:
            try:
                conn, _ = srv.accept()
                conn.sendall(b"TEST-BANNER 1.0\r\n")
                conn.close()
            except OSError:
                break

    threading.Thread(target=run, daemon=True).start()
    yield port
    srv.close()


def test_open_port_with_banner(server):
    r = scan_port("127.0.0.1", server, timeout=1, banner=True)
    assert r.state == "open"
    assert r.banner == "TEST-BANNER 1.0"


def test_banner_control_characters_are_replaced():
    # a hostile service must not be able to send escape codes to our terminal
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def run():
        conn, _ = srv.accept()
        conn.sendall(b"\x1b]0;owned\x07\x1b[31mRED\x1b[0m banner\r\n")
        conn.close()

    threading.Thread(target=run, daemon=True).start()
    try:
        r = scan_port("127.0.0.1", port, timeout=1, banner=True)
    finally:
        srv.close()
    assert r.banner == "?]0;owned??[31mRED?[0m banner"


def test_closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert scan_port("127.0.0.1", port, timeout=0.5).state == "closed"


def test_scan_returns_only_open(server):
    results = scan("127.0.0.1", [server, 1], threads=5, timeout=0.5)
    assert [r.port for r in results] == [server]
