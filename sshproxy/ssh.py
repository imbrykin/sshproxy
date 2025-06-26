import os
import json
import logging
import sys
import termios
import tty
import select
import codecs
from datetime import datetime
from ptyprocess import PtyProcessUnicode

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def run_ssh_session(user: str, host: str, port: int):
    keyfile = os.getenv("KEY_FILE", "/etc/sshproxy/proxy_keys/external_key1")
    log_dir = os.getenv("LOG_DIR", "/var/log/ssh-proxy")
    log_file_name = os.getenv("LOG_FILE", "sshproxy_events.json")
    commands_file = os.path.join(log_dir, log_file_name)

    ssh_cmd = ["ssh", "-i", keyfile, f"{user}@{host}", "-p", str(port)]
    initiator = os.getenv("SUDO_USER") or os.getlogin()
    pid = os.getpid()

    os.makedirs(log_dir, exist_ok=True)

    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "initiator": initiator,
        "target_user": user,
        "target_host": host,
        "target_port": port,
        "pid": pid,
        "action": "ssh_session_start"
    }
    with open(commands_file, "a") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")

    proc = PtyProcessUnicode.spawn(ssh_cmd)
    buffer = ""
    arrow_state = None
    arrow_count = 0
    arrow_log_buffer = []

    old_settings = termios.tcgetattr(sys.stdin)
    tty.setraw(sys.stdin.fileno())

    decoder = codecs.getincrementaldecoder("utf-8")()
    input_buffer = b""

    try:
        while proc.isalive():
            rlist, _, _ = select.select([proc.fd, sys.stdin], [], [], 0.1)

            if proc.fd in rlist:
                try:
                    data = proc.read(1024)
                    sys.stdout.write(data)
                    sys.stdout.flush()
                except EOFError:
                    break

            if sys.stdin in rlist:
                try:
                    ch_byte = os.read(sys.stdin.fileno(), 1)
                    input_buffer += ch_byte
                    try:
                        ch = decoder.decode(input_buffer)
                        input_buffer = b""
                    except UnicodeDecodeError:
                        continue

                    if ch == '\x1b':
                        esc_seq = os.read(sys.stdin.fileno(), 2).decode(errors="ignore")
                        proc.write(ch + esc_seq)
                        if esc_seq in ('[A', '[B'):
                            arrow = '↑' if esc_seq == '[A' else '↓'
                            if arrow_state == arrow:
                                arrow_count += 1
                            else:
                                if arrow_state:
                                    arrow_log_buffer.append((arrow_state, arrow_count))
                                arrow_state = arrow
                                arrow_count = 1
                        buffer = ''
                        continue
                    else:
                        if arrow_state:
                            arrow_log_buffer.append((arrow_state, arrow_count))
                            for direction, count in arrow_log_buffer:
                                log_command(f"[{direction} x{count}]", initiator, user, host, port, pid, commands_file)
                            arrow_log_buffer.clear()
                            arrow_state = None
                            arrow_count = 0

                    proc.write(ch)

                    if ch == '\x7f':
                        buffer = buffer[:-1]
                    elif ch == '\x15':
                        buffer = ''
                    elif ch == '\x03':
                        buffer = ''
                        continue
                    elif ch == '\t':
                        buffer += '<TAB>'
                    elif ch == '\r':
                        command = buffer.strip()
                        buffer = ''
                        if command and any(c.isalnum() for c in command) and not command.startswith(":"):
                            log_command(command, initiator, user, host, port, pid, commands_file)
                    else:
                        buffer += ch

                except Exception:
                    continue

    finally:
        if arrow_state:
            arrow_log_buffer.append((arrow_state, arrow_count))
        for direction, count in arrow_log_buffer:
            log_command(f"[{direction} x{count}]", initiator, user, host, port, pid, commands_file)
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
        proc.close(force=True)

def log_command(raw: str, initiator, target_user, target_host, target_port, pid, commands_file):
    cleaned = raw.replace("\x1b", "").strip()
    if cleaned:
        event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "initiator": initiator,
            "target_user": target_user,
            "target_host": target_host,
            "target_port": target_port,
            "pid": pid,
            "action": "ssh_command",
            "command": cleaned
        }
        with open(commands_file, "a") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--user", required=True)
    parser.add_argument("-h", "--host", required=True)
    parser.add_argument("-p", "--port", type=int, default=22)
    args = parser.parse_args()

    run_ssh_session(args.user, args.host, args.port)