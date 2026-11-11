import csv
import json
import socket
import threading
import time

import pytest

from portscanner import cli, scanner
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


@pytest.mark.parametrize("bad", ["0", "70000", "30-20", "", " , ", "abc", "1-", "22-abc"])
def test_parse_invalid(bad):
    with pytest.raises(ValueError):
        parse_ports(bad)


def test_parse_error_message_is_readable():
    with pytest.raises(ValueError, match="Not a port number: 'abc'"):
        parse_ports("abc")


def test_huge_range_is_rejected_before_it_is_built():
    started = time.time()
    with pytest.raises(ValueError, match="between 1 and 65535"):
        parse_ports("1-999999999")
    assert time.time() - started < 1


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


def test_closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert scan_port("127.0.0.1", port, timeout=0.5).state == "closed"


def test_scan_returns_only_open(server):
    results = scan("127.0.0.1", [server, 1], threads=5, timeout=0.5)
    assert [r.port for r in results] == [server]


def test_ipv6_target():
    try:
        srv = socket.socket(socket.AF_INET6)
        srv.bind(("::1", 0))
    except OSError:
        pytest.skip("IPv6 loopback is not available here")
    srv.listen(1)
    try:
        assert scanner.resolve_target("::1") == "::1"
        assert scan_port("::1", srv.getsockname()[1], timeout=1).state == "open"
    finally:
        srv.close()


def test_zero_timeout_and_zero_threads_are_refused(server):
    # settimeout(0) is non-blocking: the open port used to be reported as closed
    with pytest.raises(ValueError):
        scan("127.0.0.1", [server], timeout=0)
    with pytest.raises(ValueError):
        scan("127.0.0.1", [server], threads=0)
    for argv in (["127.0.0.1", "--timeout", "0"], ["127.0.0.1", "--timeout", "-1"], ["127.0.0.1", "-t", "0"]):
        with pytest.raises(SystemExit) as exit_info:
            cli.main(argv)
        assert exit_info.value.code == 2


def test_out_of_file_descriptors_is_an_error_not_a_closed_port(monkeypatch):
    def no_more_sockets(*args, **kwargs):
        raise OSError(24, "Too many open files")

    monkeypatch.setattr(scanner.socket, "socket", no_more_sockets)
    with pytest.raises(OSError):
        scan_port("127.0.0.1", 80)


def test_thread_count_stays_below_the_descriptor_limit(monkeypatch):
    resource = pytest.importorskip("resource")
    monkeypatch.setattr(resource, "getrlimit", lambda _: (64, 64))
    assert scanner.usable_threads(400) == 64 - scanner.RESERVED_FDS
    assert scanner.usable_threads(10) == 10


def test_banner_is_made_printable():
    assert scanner.clean_banner("SSH-2.0\x1b[2J\x1b[1;1Hfake") == "SSH-2.0?[2J?[1;1Hfake"


def test_8443_gets_no_plain_http_request():
    assert 8443 not in scanner.HTTP_PORTS


def test_output_folder_is_created_and_csv_is_safe(server, tmp_path, capsys):
    target = tmp_path / "results" / "scan.json"
    assert cli.main(["127.0.0.1", "-p", str(server), "-o", str(target)]) == 0
    assert json.loads(target.read_text())["results"][0]["port"] == server

    upper = tmp_path / "OUT.CSV"
    assert cli.main(["127.0.0.1", "-p", str(server), "-b", "-o", str(upper)]) == 0
    rows = list(csv.DictReader(upper.open(newline="")))
    assert rows[0]["port"] == str(server) and rows[0]["banner"] == "TEST-BANNER 1.0"

    assert cli.csv_safe("=cmd|' /C calc'!A0") == "'=cmd|' /C calc'!A0"
    assert cli.csv_safe("SSH-2.0-OpenSSH") == "SSH-2.0-OpenSSH"
    assert cli.csv_safe(None) == ""


def test_unknown_output_extension_is_refused_before_the_scan(capsys):
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["127.0.0.1", "-o", "result.txt"])
    assert exit_info.value.code == 2
    assert ".json or .csv" in capsys.readouterr().err


def test_empty_port_list_is_an_error(capsys):
    assert cli.main(["127.0.0.1", "-p", ""]) == 1
    assert "No ports given" in capsys.readouterr().err
