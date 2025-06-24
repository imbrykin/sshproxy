import os
import yaml
import fnmatch
import subprocess
import logging

logger = logging.getLogger(__name__)

CONFIG_PATH = "/opt/sshproxy/config.yaml"

def load_config():
    try:
        with open(CONFIG_PATH, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error("Failed to load config: %s", e)
        return {}

def get_user_groups(user: str):
    try:
        result = subprocess.run(
            ["id", "-nG", user],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            check=True
        )
        return result.stdout.strip().split()
    except subprocess.CalledProcessError:
        logger.warning("Failed to get groups for user %s", user)
        return []

def is_access_allowed(user: str, host: str) -> bool:
    config = load_config()
    rules = config.get("access_control", {})
    user_groups = get_user_groups(user)

    logger.debug("User %s groups: %s", user, user_groups)
    logger.debug("Access rules: %s", rules)

    for group in user_groups:
        policy = rules.get(group)
        if not policy:
            logger.debug("No policy found for group: %s", group)
            continue
        for pattern in policy.get("allow_hosts", []):
            logger.debug("Checking host %s against pattern %s from group %s", host, pattern, group)
            if fnmatch.fnmatch(host, pattern):
                logger.info("Access allowed by group '%s' and pattern '%s'", group, pattern)
                return True

    logger.warning("Access denied by policy: user=%s groups=%s host=%s", user, user_groups, host)
    return False