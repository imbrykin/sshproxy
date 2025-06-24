import subprocess
import logging

logger = logging.getLogger(__name__)


def check_access(user: str, host: str) -> bool:
    try:
        subprocess.run(
            ["ipa", "user-show", user],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        subprocess.run(
            ["ipa", "host-show", host],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        result = subprocess.run(
            ["sssctl", "user-checks", user, "-s", "sshd"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )

        logger.debug("sssctl stdout:\n%s", result.stdout.strip())
        logger.debug("sssctl stderr:\n%s", result.stderr.strip())

        # Важно: pam_acct_mgmt попадает в stderr
        if "pam_acct_mgmt: Success" in result.stderr:
            logger.info("SSSD access GRANTED for %s@%s", user, host)
            return True
        else:
            logger.warning("SSSD access DENIED for %s@%s", user, host)
            return False

    except subprocess.CalledProcessError as e:
        logger.exception("IPA command failed for %s@%s: %s", user, host, e)
        return False
    except FileNotFoundError as e:
        logger.error("Required command not found: %s", e)
        return False
    except Exception as e:
        logger.exception("Unexpected error during access check for %s@%s: %s", user, host, e)
        return False