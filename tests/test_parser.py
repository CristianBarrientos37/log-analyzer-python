from log_analyzer.parser import (
    parse_line,
    parse_file,
    EVENT_FAILED_LOGIN,
    EVENT_SUCCESSFUL_LOGIN,
    EVENT_INVALID_USER,
    EVENT_SUDO_COMMAND,
    EVENT_UNKNOWN,
)


def test_parse_failed_password():
    line = "Oct 17 18:28:46 ubuntu-victim sshd[1001]: Failed password for labuser from 10.10.10.40 port 40001 ssh2"
    event = parse_line(line, year=2026)
    assert event is not None
    assert event.event_type == EVENT_FAILED_LOGIN
    assert event.user == "labuser"
    assert event.src_ip == "10.10.10.40"
    assert event.port == 40001
    assert event.timestamp.month == 10
    assert event.timestamp.day == 17
    assert event.timestamp.hour == 18


def test_parse_failed_password_invalid_user_variant():
    # sshd a veces loguea así cuando el usuario no existe
    line = "Oct 17 19:05:10 host sshd[2001]: Failed password for invalid user admin from 203.0.113.50 port 51000 ssh2"
    event = parse_line(line, year=2026)
    assert event.event_type == EVENT_FAILED_LOGIN
    assert event.user == "admin"
    assert event.src_ip == "203.0.113.50"


def test_parse_accepted_password():
    line = "Oct 17 18:29:21 ubuntu-victim sshd[1007]: Accepted password for labuser from 10.10.10.40 port 40007 ssh2"
    event = parse_line(line, year=2026)
    assert event.event_type == EVENT_SUCCESSFUL_LOGIN
    assert event.user == "labuser"
    assert event.src_ip == "10.10.10.40"


def test_parse_accepted_publickey():
    line = "Oct 17 20:00:00 ubuntu-victim sshd[3001]: Accepted publickey for deploy from 198.51.100.5 port 22222 ssh2"
    event = parse_line(line, year=2026)
    assert event.event_type == EVENT_SUCCESSFUL_LOGIN
    assert event.user == "deploy"


def test_parse_invalid_user():
    line = "Oct 17 19:05:10 ubuntu-victim sshd[2001]: Invalid user admin from 203.0.113.50 port 51000"
    event = parse_line(line, year=2026)
    assert event.event_type == EVENT_INVALID_USER
    assert event.user == "admin"
    assert event.src_ip == "203.0.113.50"


def test_parse_sudo_command():
    line = "Oct 17 19:40:23 ubuntu-victim sudo:   labuser : TTY=pts/0 ; PWD=/home/labuser ; USER=root ; COMMAND=/usr/bin/apt update"
    event = parse_line(line, year=2026)
    assert event.event_type == EVENT_SUDO_COMMAND
    assert event.user == "labuser"
    assert event.extra["target_user"] == "root"
    assert event.extra["command"] == "/usr/bin/apt update"


def test_parse_unrecognized_sshd_message_is_unknown():
    line = "Oct 17 18:29:21 ubuntu-victim sshd[1007]: pam_unix(sshd:session): session opened for user labuser(uid=1001) by (uid=0)"
    event = parse_line(line, year=2026)
    assert event.event_type == EVENT_UNKNOWN


def test_parse_blank_line_returns_none():
    assert parse_line("", year=2026) is None
    assert parse_line("   \n", year=2026) is None


def test_parse_non_syslog_line_returns_none():
    assert parse_line("this is not a syslog line", year=2026) is None


def test_parse_file_reads_fixture():
    events = list(parse_file("tests/fixtures/sample_auth.log", year=2026))
    assert len(events) == 15
    failed = [e for e in events if e.event_type == EVENT_FAILED_LOGIN]
    assert len(failed) == 6
