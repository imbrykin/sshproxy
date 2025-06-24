import os
import subprocess
import logging
from datetime import datetime
from sshproxy.ports import get_free_port, log_assigned_port

logger = logging.getLogger(__name__)

def run_ssh_session(user: str, host: str, port: int):
    keyfile = "/etc/sshproxy/proxy_keys/external_key1"
    ssh_cmd = ["ssh", "-i", keyfile, f"{user}@{host}", "-p", str(port)]

    # Путь к лог-файлу
    log_dir = "/var/log/ssh-proxy/sessions"
    os.makedirs(log_dir, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    session_filename = f"{user}@{host}_{timestamp}.log"
    log_file = os.path.join(log_dir, session_filename)

    # Команда через script для логирования всей сессии
    full_cmd = ["script", "-q", "-f", log_file, "--"] + ssh_cmd

    logger.info("Starting SSH session to %s@%s:%d", user, host, port)
    logger.info("Session log: %s", log_file)

    try:
        subprocess.run(full_cmd)
    except Exception as e:
        logger.exception("Failed to start SSH session via script: %s", e)
