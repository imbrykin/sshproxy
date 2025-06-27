import os
import re
import json
import time
from datetime import datetime
import logging

LOG_FILE = "/var/log/ssh-proxy/parser.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

SESSIONS_DIR = "/var/log/ssh-proxy/sessions"
OUTPUT_FILE = "/var/log/ssh-proxy/sshproxy_commands.json"
PROCESSED_LINES = {}

ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
prompt_pattern = re.compile(r'^\[(?P<user>[\w.-]+)@(?P<host>[\w.-]+)\s+[~\w/\.-]*\]\$\s*(?P<cmd>.*)$')


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
                "target_port": 22
            }
    return None


def run_parser():
    logging.info("Starting SSH log parser...")
    while True:
        logging.debug("Scanning for log files...")
        log_files = [f for f in os.listdir(SESSIONS_DIR) if f.startswith("session_") and f.endswith(".log")]
        for fname in log_files:
            full_path = os.path.join(SESSIONS_DIR, fname)
            logging.debug(f"Processing file: {full_path}")

            metadata = extract_metadata_from_filename(fname)
            if not metadata:
                logging.warning(f"Could not extract metadata from {fname}")
                continue

            if full_path not in PROCESSED_LINES:
                PROCESSED_LINES[full_path] = 0

            try:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    f.seek(PROCESSED_LINES[full_path])
                    lines = f.readlines()
                    PROCESSED_LINES[full_path] = f.tell()
                    logging.debug(f"Read {len(lines)} new lines from {fname}")
            except Exception as e:
                logging.error(f"Failed to read {full_path}: {e}")
                continue

            for raw_line in lines:
                line = ansi_escape.sub('', raw_line.strip())
                logging.debug(f"Checking line: {line}")
                match = prompt_pattern.match(line)

                if match:
                    cmd = match.group("cmd").strip()
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
                        logging.info(f"Captured command: {cmd}")
                        try:
                            with open(OUTPUT_FILE, "a") as out:
                                out.write(json.dumps(record) + "\n")
                        except Exception as e:
                            logging.error(f"Failed to write to output file: {e}")
                else:
                    logging.debug(f"No match: {line}")
        time.sleep(1)


if __name__ == "__main__":
    run_parser()