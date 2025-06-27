import os
import re
import json
import time
import hashlib
from datetime import datetime
import logging

LOG_FILE = "/var/log/ssh-proxy/parser.log"
HASHES_FILE = "/var/log/ssh-proxy/session_hashes.json"
COMMANDS_SEEN_FILE = "/var/log/ssh-proxy/seen_commands.json"

with open(LOG_FILE, "w") as log_init:
    log_init.write("")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

SESSIONS_DIR = "/var/log/ssh-proxy/sessions"
OUTPUT_FILE = "/var/log/ssh-proxy/sshproxy_commands.json"
PROCESSED_HASHES = {}
SEEN_COMMANDS = set()

ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
prompt_pattern = re.compile(r'^.*\[(?P<user>[\w.-]+)@(?P<host>[\w.-]+)\s+[~\w/\.-]*\]\$\s*(?P<cmd>.*)$')
sftp_pattern = re.compile(r'^sftp>\s*(?P<cmd>.*)$')

def load_hashes():
    if os.path.exists(HASHES_FILE):
        try:
            with open(HASHES_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Failed to load hashes: {e}")
    return {}

def save_hashes():
    try:
        with open(HASHES_FILE, 'w') as f:
            json.dump(PROCESSED_HASHES, f)
    except Exception as e:
        logging.error(f"Failed to save hashes: {e}")

def load_seen_commands():
    if os.path.exists(COMMANDS_SEEN_FILE):
        try:
            with open(COMMANDS_SEEN_FILE, 'r') as f:
                return set(json.load(f))
        except Exception as e:
            logging.error(f"Failed to load seen commands: {e}")
    return set()

def save_seen_commands():
    try:
        with open(COMMANDS_SEEN_FILE, 'w') as f:
            json.dump(list(SEEN_COMMANDS), f)
    except Exception as e:
        logging.error(f"Failed to save seen commands: {e}")

def compute_hash(file_path):
    try:
        hasher = hashlib.md5()
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        logging.error(f"Failed to compute hash for {file_path}: {e}")
        return None

def extract_metadata_from_filename(filename):
    if filename.startswith("session_") and "_" in filename:
        parts = filename.replace("session_", "").replace(".log", "").split("_")
        if len(parts) >= 3:
            return {
                "timestamp": parts[0],
                "initiator": parts[1],
                "target_host": parts[2],
                "pid": os.getpid(),
                "target_user": "alaris",
                "target_port": 22,
                "mode": "sftp" if "sftp" in parts[2].lower() else "ssh"
            }
    return None

def run_parser():
    global PROCESSED_HASHES, SEEN_COMMANDS
    logging.info("Starting SSH log parser...")
    PROCESSED_HASHES = load_hashes()
    SEEN_COMMANDS = load_seen_commands()

    while True:
        logging.debug("Scanning for log files...")
        log_files = [f for f in os.listdir(SESSIONS_DIR) if f.startswith("session_") and f.endswith(".log")]

        for fname in log_files:
            full_path = os.path.join(SESSIONS_DIR, fname)
            file_hash = compute_hash(full_path)

            if not file_hash:
                continue
            if PROCESSED_HASHES.get(fname) == file_hash:
                logging.debug(f"No changes in file: {fname}")
                continue

            metadata = extract_metadata_from_filename(fname)
            if not metadata:
                logging.warning(f"Could not extract metadata from {fname}")
                continue

            try:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    logging.debug(f"Read {len(lines)} lines from {fname}")
            except Exception as e:
                logging.error(f"Failed to read {full_path}: {e}")
                continue

            for raw_line in lines:
                line = ansi_escape.sub('', raw_line.strip())
                logging.debug(f"Checking line: {line}")

                action_type = "ssh_command"
                cmd = None

                if metadata.get("mode") == "sftp":
                    match = sftp_pattern.match(line)
                    if match:
                        cmd = match.group("cmd").strip()
                        action_type = "sftp_command"
                else:
                    match = prompt_pattern.match(line)
                    if match:
                        cmd = match.group("cmd").strip()

                if cmd:
                    dedup_key = f"{metadata['initiator']}|{metadata['target_host']}|{metadata['pid']}|{cmd}"
                    if dedup_key in SEEN_COMMANDS:
                        logging.debug(f"Duplicate command skipped: {cmd}")
                        continue
                    SEEN_COMMANDS.add(dedup_key)

                    record = {
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "initiator": metadata["initiator"],
                        "target_user": metadata["target_user"],
                        "target_host": metadata["target_host"],
                        "target_port": metadata["target_port"],
                        "pid": metadata["pid"],
                        "action": action_type,
                        "command": cmd
                    }
                    logging.info(f"Captured {action_type}: {cmd}")
                    try:
                        with open(OUTPUT_FILE, "a") as out:
                            out.write(json.dumps(record) + "\n")
                    except Exception as e:
                        logging.error(f"Failed to write to output file: {e}")
                else:
                    logging.debug(f"No match: {line}")

            PROCESSED_HASHES[fname] = file_hash
            save_hashes()
            save_seen_commands()

        time.sleep(2)

if __name__ == "__main__":
    run_parser()
