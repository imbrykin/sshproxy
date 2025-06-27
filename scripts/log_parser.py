import os
import re
import json
import time
from datetime import datetime

LOG_DIR = "/var/log/ssh-proxy"
SESSIONS_DIR = os.path.join(LOG_DIR, "sessions")
COMMANDS_LOG = os.path.join(LOG_DIR, "sshproxy_commands.json")
SEEN = set()  # Уникальные ключи: <pid>:<command>:<timestamp>


ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
prompt_pattern = re.compile(r'^\[.*@.*\]\$\s+(.*)')

def parse_filename(filename):
    parts = filename.replace("session_", "").replace(".log", "").split("_")
    return {
        "timestamp": parts[0],
        "initiator": parts[1],
        "target_host": parts[2],
        "pid": None  # можем добавить позже, если начнем вытаскивать PID из других метаданных
    }

def process_log(filepath):
    meta = parse_filename(os.path.basename(filepath))
    commands = []

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                cleaned = ansi_escape.sub('', line.strip())
                match = prompt_pattern.match(cleaned)
                if match:
                    cmd = match.group(1).strip()
                    if cmd:
                        key = f"{meta['initiator']}:{meta['target_host']}:{cmd}"
                        if key not in SEEN:
                            SEEN.add(key)
                            commands.append({
                                "timestamp": datetime.utcnow().isoformat() + "Z",
                                "initiator": meta["initiator"],
                                "target_user": "alaris",
                                "target_host": meta["target_host"],
                                "target_port": 22,
                                "pid": meta["pid"] or 0,
                                "action": "ssh_command",
                                "command": cmd
                            })
    except Exception as e:
        print(f"[WARN] Failed to process {filepath}: {e}")
    return commands

def main():
    while True:
        for fname in os.listdir(SESSIONS_DIR):
            if fname.startswith("session_") and fname.endswith(".log"):
                full_path = os.path.join(SESSIONS_DIR, fname)
                cmds = process_log(full_path)
                if cmds:
                    with open(COMMANDS_LOG, "a") as out:
                        for c in cmds:
                            out.write(json.dumps(c, ensure_ascii=False) + "\n")
        time.sleep(2)

if __name__ == "__main__":
    main()
