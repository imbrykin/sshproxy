import os
import json
import logging
import sys
import termios
import tty
import select
import re
from datetime import datetime
from ptyprocess import PtyProcessUnicode

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Регулярки для чистки ANSI-последовательностей и прочего шума
ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
shell_prompt_prefix = re.compile(r'^\]0;.*?\x07')
decorations = re.compile(r'[\x07\x1b].*?[\x07m]|[\r]|\[?2004[hl]')

def run_ssh_session(user: str, host: str, port: int):
    keyfile = "/etc/sshproxy/proxy_keys/external_key1"
    ssh_cmd = ["ssh", "-i", keyfile, f"{user}@{host}", "-p", str(port)]

    initiator = os.getenv("SUDO_USER") or os.getlogin()
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    pid = os.getpid()
    session_id = f"{user}@{host}_{timestamp}_{pid}.log"

    commands_file = "/var/log/ssh-proxy/loki_commands.json"
    os.makedirs("/var/log/ssh-proxy", exist_ok=True)

    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "initiator": initiator,
        "target_user": user,
        "target_host": host,
        "target_port": port,
        "session_id": session_id,
        "pid": pid,
        "action": "ssh_session_start"
    }
    with open("/var/log/ssh-proxy/loki_events.json", "a") as f:
        f.write(json.dumps(event) + "\n")

    proc = PtyProcessUnicode.spawn(ssh_cmd)
    buffer = ""

    old_settings = termios.tcgetattr(sys.stdin)
    tty.setraw(sys.stdin.fileno())

    try:
        while proc.isalive():
            rlist, _, _ = select.select([proc.fd, sys.stdin], [], [], 0.1)

            if sys.stdin in rlist:
                user_input = os.read(sys.stdin.fileno(), 1024).decode()
                proc.write(user_input)

            if proc.fd in rlist:
                try:
                    data = proc.read(1024)
                    if data:
                        sys.stdout.write(data)
                        sys.stdout.flush()
                        buffer += data

                        while "\n" in buffer:
                            line, buffer = buffer.split("\n", 1)
                            stripped = line.strip()
                            log_command(stripped, initiator, user, host, port, session_id, pid, commands_file)
                except EOFError:
                    break
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
        proc.close(force=True)


def log_command(raw: str, initiator, target_user, target_host, target_port, session_id, pid, commands_file):
    cleaned = ansi_escape.sub('', raw)
    cleaned = shell_prompt_prefix.sub('', cleaned)
    cleaned = decorations.sub('', cleaned)
    cleaned = cleaned.strip()

    # Отсекаем шум и служебный вывод
    if not cleaned:
        return
    if any(substr in cleaned for substr in [
        "Last login", "Connection to", "closed.", "logout", "Permission denied"
    ]):
        return
    if cleaned.endswith("~]$") or cleaned.startswith("[") or cleaned.startswith("total "):
        return

    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "initiator": initiator,
        "target_user": target_user,
        "target_host": target_host,
        "target_port": target_port,
        "session_id": session_id,
        "pid": pid,
        "action": "ssh_command",
        "command": cleaned
    }
    with open(commands_file, "a") as f:
        f.write(json.dumps(event) + "\n")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--user", required=True)
    parser.add_argument("-h", "--host", required=True)
    parser.add_argument("-p", "--port", type=int, default=22)
    args = parser.parse_args()

    run_ssh_session(args.user, args.host, args.port)