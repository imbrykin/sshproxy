import subprocess
import logging

logger = logging.getLogger(__name__)

def check_access(user: str, host: str) -> bool:
    try:
        result = subprocess.run(
            ["sssctl", "user-checks", user, "-s", "sshd"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )

        logger.debug("sssctl stdout:\n%s", result.stdout.strip())
        logger.debug("sssctl stderr:\n%s", result.stderr.strip())

        if "pam_acct_mgmt: Success" in result.stderr:
            logger.info("SSSD access GRANTED for %s@%s", user, host)
            return True
        else:
            logger.warning("SSSD access DENIED for %s@%s", user, host)
            return False

    except FileNotFoundError as e:
        logger.error("Required command not found: %s", e)
        return False
    except Exception as e:
        logger.exception("Unexpected error during access check for %s@%s: %s", user, host, e)
        return False