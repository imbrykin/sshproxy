import os
import sys
import json
import logging
import codecs
import select
import termios
import tty
import subprocess
from datetime import datetime
from ptyprocess import PtyProcessUnicode

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def log_command(command: str, initiator: str, user: str, host: str, port: int, pid: int, path: str):
    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "initiator": initiator,
        "target_user": user,
        "target_host": host,
        "target_port": port,
        "pid": pid,
        "action": "ssh_command",
        "command": command
    }
    with open(path, "a") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")

def run_ssh_session(user: str, host: str, port: int, mode: int):
    keyfile = os.getenv("KEY_FILE", "/etc/sshproxy/proxy_keys/external_key1")
    log_dir = os.getenv("LOG_DIR", "/var/log/ssh-proxy")
    events_file = os.path.join(log_dir, "sshproxy_events.json")
    commands_file = os.path.join(log_dir, "sshproxy_commands.json")
    os.makedirs(log_dir, exist_ok=True)

    initiator = os.getenv("SUDO_USER") or os.getlogin()
    pid = os.getpid()
    timestamp = datetime.utcnow().isoformat()

    session_type = "sftp" if mode == 1 else "ssh"

    if mode == 1:
        command = ["sftp", "-o", f"Port={port}", "-o", f"IdentityFile={keyfile}", f"{user}@{host}"]
    else:
        command = ["ssh", "-i", keyfile, f"{user}@{host}", "-p", str(port)]

    # Log session start
    with open(events_file, "a") as f:
        f.write(json.dumps({
            "timestamp": timestamp + "Z",
            "initiator": initiator,
            "target_user": user,
            "target_host": host,
            "target_port": port,
            "pid": pid,
            "action": f"{session_type}_session_start",
            "mode": session_type
        }, ensure_ascii=False) + "\n")

    proc = PtyProcessUnicode.spawn(command)
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
                        continue

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
                        command_str = buffer.strip()

                        # Вытащить предыдущую команду, если buffer пуст
                        if not command_str:
                            try:
                                command_str = proc.before.strip().split('\n')[-1]
                            except Exception:
                                command_str = ""

                        buffer = ""
                        if command_str:
                            log_command(command_str, initiator, user, host, port, pid, commands_file)

                    else:
                        buffer += ch

                except Exception:
                    continue

    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
        proc.close(force=True)

    logged_commands = get_logged_commands(commands_file)
    history_lines = fetch_bash_history(user, host, keyfile, logged_commands)
    for line in history_lines:
        log_command(line.strip(), initiator, user, host, port, pid, commands_file)

    # Log session end
    with open(events_file, "a") as f:
        f.write(json.dumps({
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "initiator": initiator,
            "target_user": user,
            "target_host": host,
            "target_port": port,
            "pid": pid,
            "action": f"{session_type}_session_end"
        }, ensure_ascii=False) + "\n")

def fetch_bash_history(target_user, target_host, keyfile, known_commands):
    try:
        result = subprocess.run([
            "ssh", "-i", keyfile, f"{target_user}@{target_host}",
            "tail", "-n", "20", "~/.bash_history"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, universal_newlines=True)

        history_lines = result.stdout.strip().splitlines()
        return [cmd for cmd in history_lines if cmd and cmd not in known_commands]

    except subprocess.CalledProcessError as e:
        logger.warning("Failed to fetch bash_history: %s", e)
        return []

def get_logged_commands(path):
    if not os.path.exists(path):
        return set()
    try:
        with open(path, "r") as f:
            return {json.loads(line)["command"] for line in f if "command" in line}
    except Exception as e:
        logger.warning("Failed to parse logged commands: %s", e)
        return set()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--user", required=True)
    parser.add_argument("-h", "--host", required=True)
    parser.add_argument("-p", "--port", type=int, required=True)
    parser.add_argument("-t", "--type", type=int, choices=[0, 1], required=True, help="0 - SSH, 1 - SFTP")
    args = parser.parse_args()

    run_ssh_session(args.user, args.host, args.port, args.type)
