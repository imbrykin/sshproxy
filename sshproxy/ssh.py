import os
import subprocess
import logging
import json
from datetime import datetime
from sshproxy.ports import get_free_port, log_assigned_port

logger = logging.getLogger(__name__)

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

    # Команда для логирования всей сессии
    full_cmd = ["script", "-q", "-f", log_file, "-c", " ".join(ssh_cmd)]

    # JSON-лог
    json_event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "initiator": initiator,
        "target_user": user,
        "target_host": host,
        "target_port": port,
        "session_log": session_filename,
        "pid": pid,
        "action": "ssh_session_start"
    }

    json_log_file = "/var/log/ssh-proxy/loki_events.json"
    try:
        with open(json_log_file, "a") as f:
            f.write(json.dumps(json_event) + "\n")
    except Exception as e:
        logger.warning("Failed to write JSON session log: %s", e)

    logger.info("Starting SSH session to %s@%s:%d", user, host, port)
    logger.info("Session log: %s", log_file)

    try:
        subprocess.run(full_cmd)
    except Exception as e:
        logger.exception("Failed to start SSH session via script: %s", e)
