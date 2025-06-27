import os
import re
import json
import time
from datetime import datetime

SESSIONS_DIR = "/var/log/ssh-proxy/sessions"
OUTPUT_FILE = "/var/log/ssh-proxy/sshproxy_commands.json"
PROCESSED_LINES = {}

ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
prompt_pattern = re.compile(r'^\[.*@.*\]\$\s+(.*)')

def extract_metadata_from_filename(filename):
    # Старый формат:
    if filename.startswith("session_") and "_" in filename:
        parts = filename.replace("session_", "").replace(".log", "").split("_")
        if len(parts) >= 3:
            return {
                "timestamp": parts[0],
                "initiator": parts[1],
                "target_host": parts[2],
                "pid": os.getpid(),
                "target_user": "alaris",
                "target_port": 22
            }

    # Новый формат:
    match = re.match(r'^(\d{4}\.\d{2}\.\d{2}-\d{2}:\d{2}:\d{2})-([\w\.@-]+)-([\w\-\.@]+)@([\w\.-]+)\.log$', filename)
    if match:
        timestamp, initiator, target_user, target_host = match.groups()
        return {
            "timestamp": timestamp.replace(".", "-").replace(":", ""),
            "initiator": initiator,
            "target_user": target_user,
            "target_host": target_host,
            "target_port": 22,
            "pid": os.getpid()
        }

    return None

def follow_log_file(path, start_from=0):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        f.seek(start_from)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line.strip()

def run_parser():
    print("[INFO] Starting SSH log parser...")
    while True:
        log_files = [f for f in os.listdir(SESSIONS_DIR) if f.startswith("session_") and f.endswith(".log")]
        for fname in log_files:
            full_path = os.path.join(SESSIONS_DIR, fname)
            metadata = extract_metadata_from_filename(fname)
            if not metadata:
                continue

            if full_path not in PROCESSED_LINES:
                PROCESSED_LINES[full_path] = 0

            try:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    f.seek(PROCESSED_LINES[full_path])
                    lines = f.readlines()
                    PROCESSED_LINES[full_path] = f.tell()
            except Exception as e:
                continue

            for raw_line in lines:
                line = ansi_escape.sub('', raw_line.strip())
                match = prompt_pattern.match(line)
                if match:
                    cmd = match.group(1).strip()
                    if cmd:
                        record = {
                            "timestamp": datetime.utcnow().isoformat() + "Z",
                            "initiator": metadata["initiator"],
                            "target_user": metadata["target_user"],
                            "target_host": metadata["target_host"],
                            "target_port": metadata["target_port"],
                            "pid": metadata["pid"],
                            "action": "ssh_command",
                            "command": cmd
                        }
                        with open(OUTPUT_FILE, "a") as out:
                            out.write(json.dumps(record) + "\n")
        time.sleep(1)

if __name__ == "__main__":
    run_parser()