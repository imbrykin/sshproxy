import subprocess
import logging
from sshproxy.config import load_config, get_user_groups

logger = logging.getLogger(__name__)

def check_access(user: str, host: str, service: str = "sshd") -> bool:
    config = load_config()
    rules = config.get("access_control", {})
    user_groups = get_user_groups(user)

    logger.debug("User %s belongs to groups: %s", user, user_groups)

    for group in user_groups:
        rule_config = rules.get(group)
        if not rule_config:
            continue

        hbac_rule = rule_config.get("hbac_rule")
        allowed_services = rule_config.get("allow_services", [])

        if service not in allowed_services:
            logger.info("Access denied: service '%s' not allowed by config for group '%s'", service, group)
            continue

        try:
            result = subprocess.run(
                ["sssctl", "user-checks", user, "-s", service],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            if "pam_acct_mgmt: Success" in result.stderr:
                logger.info("HBAC access granted via rule '%s' for group '%s'", hbac_rule, group)
                return True
            else:
                logger.info("Group '%s': HBAC rule does not permit service '%s'", group, service)
        except Exception as e:
            logger.warning("Error checking HBAC rule for group '%s': %s", group, str(e))

    logger.warning("No HBAC rule permits user %s to use service %s", user, service)
    return False
