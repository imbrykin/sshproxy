import os
import subprocess
import logging
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
    session_filename = f"{user}@{host}_{timestamp}_{pid}.log"
    log_file = os.path.join(log_dir, session_filename)

    initiator = os.getenv("SUDO_USER") or os.getlogin()

    # Временный файл с заголовком
    header_file = f"/tmp/sshproxy_header_{pid}.txt"
    try:
        with open(header_file, "w") as f:
            f.write(f"Script started on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S+00:00')} by {initiator}\n")
    except Exception as e:
        logger.warning("Failed to write header: %s", e)

    script_log_tmp = f"/tmp/sshproxy_session_{pid}.tmp"
    full_cmd = ["script", "-q", "-f", script_log_tmp, "-c", " ".join(ssh_cmd)]

    logger.info("Starting SSH session to %s@%s:%d", user, host, port)
    logger.info("Session log: %s", log_file)

    # Запись mapping
    hostname_log = "/var/log/ssh-proxy/hostnames.txt"
    try:
        with open(hostname_log, "a") as f:
            f.write(f"{datetime.utcnow().isoformat()}Z | {initiator} -> {user}@{host}:{port} => {session_filename}\n")
    except Exception as e:
        logger.warning("Failed to log hostname mapping: %s", e)

    try:
        subprocess.run(full_cmd)
        # Объединяем header и лог
        with open(log_file, "wb") as final_log:
            with open(header_file, "rb") as h, open(script_log_tmp, "rb") as s:
                final_log.write(h.read())
                final_log.write(s.read())
    except Exception as e:
        logger.exception("Failed to start SSH session via script: %s", e)
    finally:
        os.remove(header_file)
        os.remove(script_log_tmp)