import os
import yaml
import fnmatch
import subprocess
import logging

logger = logging.getLogger(__name__)

CONFIG_PATH = "/etc/sshproxy/config.yaml"

def load_config():
    try:
        with open(CONFIG_PATH, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error("Failed to load config: %s", e)
        return {}

def get_user_groups(user: str):
    try:
        result = subprocess.run(["id", "-nG", user], capture_output=True, text=True, check=True)
        return result.stdout.strip().split()
    except subprocess.CalledProcessError:
        logger.warning("Failed to get groups for user %s", user)
        return []

def is_access_allowed(user: str, host: str) -> bool:
    config = load_config()
    rules = config.get("access_control", {})
    user_groups = get_user_groups(user)

    for group in user_groups:
        policy = rules.get(group)
        if not policy:
            continue
        for pattern in policy.get("allow_hosts", []):
            if fnmatch.fnmatch(host, pattern):
                logger.info("Access allowed by group '%s' pattern '%s'", group, pattern)
                return True
