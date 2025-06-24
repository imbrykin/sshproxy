import os
import getpass
import logging
from sshproxy.ipa import check_access
from sshproxy.ssh import run_ssh_session
from sshproxy.config import is_access_allowed

logger = logging.getLogger(__name__)

ALLOWED_TARGET_USER = "alaris"

def start_session(host: str, user: str, mode: int, port: int):
    caller_user = os.getenv("SUDO_USER") or getpass.getuser()

    if user != ALLOWED_TARGET_USER:
        logger.warning("Target user must be '%s', got '%s'. Aborting.", ALLOWED_TARGET_USER, user)
        print(f"[ERROR] You must use '-u {ALLOWED_TARGET_USER}' to run this command.")
        return

    if not check_access(caller_user, host):
        logger.warning("HBAC access denied for initiator %s to host %s", caller_user, host)
        print(f"[ERROR] Access denied for user {caller_user} to host {host} via HBAC policy.")
        return

    if not is_access_allowed(caller_user, host):
        logger.warning("Access policy denied %s -> %s", caller_user, host)
        print(f"[ERROR] Policy restriction: {caller_user} is not allowed to connect to {host}")
        return

    logger.info("Session starting: initiator=%s, target=%s@%s:%d [mode=%d]", caller_user, user, host, port, mode)

    if mode == 0:
        run_ssh_session(user, host, port)
    elif mode == 1:
        print("[ERROR] SFTP proxy mode is not implemented.")
        logger.error("Attempted SFTP mode but it's not implemented.")
    else:
        logger.error("Unknown mode: %s", mode)
        print("[ERROR] Unknown mode. Use 0 for SSH or 1 for SFTP.")
