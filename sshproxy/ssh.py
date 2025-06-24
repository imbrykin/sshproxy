import os
import subprocess
import logging
import json
import re
import threading
import time
from datetime import datetime

logger = logging.getLogger(__name__)

ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
backspace_re = re.compile(r'.\x08')

def clean_command(raw: str) -> str:
    no_ansi = ansi_escape.sub('', raw)
    while '\x08' in no_ansi:
        no_ansi = backspace_re.sub('', no_ansi)
    return no_ansi.replace("^C", "").strip()


def run_ssh_session(user: str, host: str, port: int):
    keyfile = "/etc/sshproxy/proxy_keys/external_key1"
    ssh_cmd = ["ssh", "-i", keyfile, f"{user}@{host}", "-p", str(port)]

    log_dir = "/var/log/ssh-proxy/sessions"
    os.makedirs(log_dir, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    pid = os.getpid()
    initiator = os.getenv("SUDO_USER") or os.getlogin()
    session_filename = f"{user}@{host}_{timestamp}_{pid}.log"
    log_file = os.path.join(log_dir, session_filename)

    json_log_file = "/var/log/ssh-proxy/loki_events.json"

    session_start_event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "initiator": initiator,
        "target_user": user,
        "target_host": host,
        "target_port": port,
        "session_log": session_filename,
        "pid": pid,
        "session_id": session_filename,
        "action": "ssh_session_start"
    }

    try:
        with open(json_log_file, "a") as f:
            f.write(json.dumps(session_start_event) + "\n")
    except Exception as e:
        logger.warning("Failed to write JSON session start: %s", e)

    parser_thread = threading.Thread(
        target=live_parse,
        args=(log_file, initiator, user, host, session_filename, port, pid),
        daemon=True
    )
    parser_thread.start()

    full_cmd = ["script", "--return", "-q", "-f", log_file, "-c", " ".join(ssh_cmd)]

    try:
        subprocess.run(full_cmd)
    except Exception as e:
        logger.exception("Failed to run SSH session: %s", e)


def live_parse(log_file, initiator, target_user, target_host, session_id, target_port, pid):
    commands_file = "/var/log/ssh-proxy/loki_commands.json"
    command_regex = re.compile(r"\[\s*(?P<user>\w+)@\S+.*?\]\s*[#$]\s+(.*)")

    logger.info("[live_parse] Waiting for log file: %s", log_file)

    # Ждём появления файла
    timeout = 10  # секунд
    waited = 0
    while not os.path.exists(log_file) and waited < timeout:
        time.sleep(0.2)
        waited += 0.2

    if not os.path.exists(log_file):
        logger.error("[live_parse] File %s not created after %d seconds", log_file, timeout)
        return

    logger.info("[live_parse] Start reading: %s", log_file)

    try:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue

                match = command_regex.search(line.strip())
                if match:
                    raw_command = match.group(2)
                    command = clean_command(raw_command)
                    if command:
                        event = {
                            "timestamp": datetime.utcnow().isoformat() + "Z",
                            "initiator": initiator,
                            "target_user": target_user,
                            "target_host": target_host,
                            "target_port": target_port,
                            "session_id": session_id,
                            "pid": pid,
                            "action": "ssh_command",
                            "command": command
                        }
                        with open(commands_file, "a", encoding='utf-8') as outf:
                            outf.write(json.dumps(event) + "\n")
    except Exception as e:
        logger.warning("[live_parse] Error: %s", e)