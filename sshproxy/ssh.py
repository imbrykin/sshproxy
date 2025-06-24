import os
import pty
import subprocess
import logging
from sshproxy.ports import get_free_port, log_assigned_port

logger = logging.getLogger(__name__)


def run_ssh_session(user: str, host: str, port: int):
    keyfile = "/etc/sshproxy/proxy_keys/external_key1"
    ssh_cmd = ["sshp", "-i", keyfile, f"{user}@{host}", "-p", str(port)]

    logger.info("Starting SSH session to %s@%s:%d", user, host, port)

    try:
        pty.spawn(ssh_cmd)
    except Exception as e:
        logger.exception("Failed to start SSH session: %s", e)
        print("Failed to spawn interactive SSH session. Falling back to subprocess...")
        subprocess.run(ssh_cmd)


def run_sftp_proxy(user: str, host: str, port: int):
    port_fwd = get_free_port()
    current_pid = os.getpid()
    log_assigned_port(user, port_fwd, current_pid)

    logger.info("Starting SFTP proxy on port %d -> %s:%d", port_fwd, host, port)
    subprocess.run([
        "sshp-nc", "-4", "-k", "-l",
        "-p", str(port_fwd),
        "-c", f"nc -4 {host} {port}"
    ])