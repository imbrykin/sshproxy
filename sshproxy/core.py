import os
import getpass
import logging
from sshproxy.ipa import check_access
from sshproxy.ssh import run_ssh_session
from sshproxy.config import is_access_allowed, load_config, get_user_groups

logger = logging.getLogger(__name__)

ALLOWED_TARGET_USER = "alaris"


def start_session(host: str, user: str, mode: int, port: int):
    caller_user = os.getenv("SUDO_USER") or getpass.getuser()

    if user != ALLOWED_TARGET_USER:
        logger.warning("Target user must be '%s', got '%s'. Aborting.", ALLOWED_TARGET_USER, user)
        print(f"[ERROR] You must use '-u {ALLOWED_TARGET_USER}' to run this command.")
        return

    service = "sshd" if mode == 0 else "ftp"

    config = load_config()
    access_control = config.get("access_control", {})
    user_groups = get_user_groups(caller_user)

    logger.debug("Checking HBAC rules for user %s (groups: %s), service: %s", caller_user, user_groups, service)

    # Проверяем HBAC-доступ хотя бы по одному правилу (группе)
    hbac_allowed = False
    for group in user_groups:
        rule_config = access_control.get(group)
        if rule_config:
            if check_access(caller_user, service, rule_config):
                hbac_allowed = True
                break
            else:
                logger.info("Group '%s': HBAC rule does not permit service '%s'", group, service)
        else:
            logger.debug("Group '%s' has no access_control rule", group)

    if not hbac_allowed:
        logger.warning("No HBAC rule permits user %s to use service %s", caller_user, service)
        print(f"[ERROR] Access denied for user {caller_user} to service '{service}' via HBAC policy.")
        return

    # Дополнительная проверка: может ли пользователь ходить на этот хост
    if not is_access_allowed(caller_user, host):
        logger.warning("Access policy denied %s -> %s", caller_user, host)
        print(f"[ERROR] Policy restriction: {caller_user} is not allowed to connect to {host}")
        return

    logger.info("Session starting: initiator=%s, target=%s@%s:%d [mode=%d]", caller_user, user, host, port, mode)

    run_ssh_session(user, host, port, mode)