import os
import sys
import json
import logging
import subprocess
import re
from datetime import datetime

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def run_ssh_session(user: str, host: str, port: int, mode: int):
    keyfile = os.getenv("KEY_FILE", "/etc/sshproxy/proxy_keys/external_key1")
    log_dir = os.getenv("LOG_DIR", "/var/log/ssh-proxy")
    events_file = os.path.join(log_dir, "sshproxy_events.json")
    sessions_dir = os.path.join(log_dir, "sessions")
    os.makedirs(sessions_dir, exist_ok=True)

    initiator = os.getenv("SUDO_USER") or os.getlogin()
    pid = os.getpid()
    timestamp = datetime.utcnow().isoformat()

    session_type = "sftp" if mode == 1 else "ssh"
    session_file = os.path.join(sessions_dir, f"session_{timestamp}_{initiator}_{host}.log")

    if mode == 1:
        command = ["sftp", "-o", f"Port={port}", "-o", f"IdentityFile={keyfile}", f"{user}@{host}"]
    else:
        command = ["ssh", "-i", keyfile, f"{user}@{host}", "-p", str(port)]

    # Log session start
    event = {
        "timestamp": timestamp + "Z",
        "initiator": initiator,
        "target_user": user,
        "target_host": host,
        "target_port": port,
        "pid": pid,
        "action": f"{session_type}_session_start",
        "mode": session_type,
        "log_file": session_file
    }
    with open(events_file, "a") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")

    try:
        subprocess.run(["script", "-q", "-f", "-c", " ".join(command), session_file], check=True)
        commands = extract_commands_from_session_log(session_file, initiator, user, host, port, pid)
        commands_file = os.path.join(log_dir, "sshproxy_commands.json")
        with open(commands_file, "a") as f:
            for cmd in commands:
                f.write(json.dumps(cmd, ensure_ascii=False) + "\n")
    except subprocess.CalledProcessError as e:
        logger.error("Session failed: %s", e)
        # Log session failure
        event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "initiator": initiator,
            "target_user": user,
            "target_host": host,
            "target_port": port,
            "pid": pid,
            "action": f"{session_type}_session_failed",
            "error": str(e),
            "log_file": session_file
        }
        with open(events_file, "a") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
        print(f"[ERROR] Session failed: {e}")
        return

    # Log session end
    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "initiator": initiator,
        "target_user": user,
        "target_host": host,
        "target_port": port,
        "pid": pid,
        "action": f"{session_type}_session_end",
        "log_file": session_file
    }
    with open(events_file, "a") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")

def extract_commands_from_session_log(log_path, initiator, user, host, port, pid):
    commands = []
    prompt_pattern = re.compile(r'^\[.*@.*\]\$\s+(.*)')
    ansi_escape = re.compile(r'(?:\x1B[@-_][0-?]*[ -/]*[@-~])')

    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                raw = line.strip()
                cleaned = ansi_escape.sub('', raw)
                match = prompt_pattern.match(cleaned)
                if match:
                    cmd = match.group(1).strip()
                    if cmd:
                        commands.append({
                            "timestamp": datetime.utcnow().isoformat() + "Z",
                            "initiator": initiator,
                            "target_user": user,
                            "target_host": host,
                            "target_port": port,
                            "pid": pid,
                            "action": "ssh_command",
                            "command": cmd
                        })
    except Exception as e:
        logger.warning("Failed to extract commands from session log: %s", e)

    return commands

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--user", required=True)
    parser.add_argument("-h", "--host", required=True)
    parser.add_argument("-p", "--port", type=int, required=True)
    parser.add_argument("-t", "--type", type=int, choices=[0, 1], required=True, help="0 - SSH, 1 - SFTP")
    args = parser.parse_args()

    run_ssh_session(args.user, args.host, args.port, args.type)
