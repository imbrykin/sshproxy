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

    keyfile = os.getenv("KEY_FILE", "/etc/sshproxy/proxy_keys/external_key1")
    log_dir = os.getenv("LOG_DIR", "/var/log/ssh-proxy")
    log_file_name = os.getenv("LOG_FILE", "sshproxy_events.json")
    commands_file = os.path.join(log_dir, log_file_name)

    ssh_cmd = ["ssh", "-i", keyfile, f"{user}@{host}", "-p", str(port)]
    initiator = os.getenv("SUDO_USER") or os.getlogin()
    pid = os.getpid()

    os.makedirs(log_dir, exist_ok=True)

    # log session start
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

                    if ch == '\x1b':  # Escape — стрелки и прочее
                        esc_seq = os.read(sys.stdin.fileno(), 2).decode(errors="ignore")
                        proc.write(ch + esc_seq)
                        if esc_seq == '[A':
                            log_command("[↑ command used]", initiator, user, host, port, pid, commands_file)
                        elif esc_seq == '[B':
                            log_command("[↓ command used]", initiator, user, host, port, pid, commands_file)
                        buffer = ''
                        continue

                    proc.write(ch)

                    if ch == '\x7f':  # Backspace
                        buffer = buffer[:-1]
                    elif ch == '\x15':  # Ctrl+U
                        buffer = ''
                    elif ch == '\x03':  # Ctrl+C
                        buffer = ''
                        continue
                    elif ch == '\t':  # Tab
                        buffer += '<TAB>'
                    elif ch == '\r':  # Enter
                        command = buffer.strip()
                        buffer = ''
                        if (
                            command
                            and any(c.isalnum() for c in command)
                            and not command.startswith(":")
                        ):
                            log_command(command, initiator, user, host, port, pid, commands_file)

                            # Если команда — TUI, сбрасываем буфер
                            tui_cmds = {"less", "vim", "nano", "top", "htop", "mc"}
                            first_word = command.split()[0]
                            if first_word in tui_cmds:
                                buffer = ''
                    else:
                        buffer += ch

                except Exception:
                    continue

    finally:
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
            #f.write(json.dumps(event) + "\n")
            f.write(json.dumps(event, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--user", required=True)
    parser.add_argument("-h", "--host", required=True)
    parser.add_argument("-p", "--port", type=int, default=22)
    args = parser.parse_args()

    run_ssh_session(args.user, args.host, args.port)