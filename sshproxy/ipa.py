import subprocess
import logging
from typing import Optional

logger = logging.getLogger(__name__)

def check_hbac_access(user: str, service: str) -> bool:
    """
    Проверяет, разрешён ли доступ пользователю по HBAC для указанного сервиса (sshd или ftp).
    Используется sssctl user-checks без Kerberos.
    """
    try:
        result = subprocess.run(
            ["sssctl", "user-checks", user, "-s", service],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )

        logger.debug("sssctl stdout:\n%s", result.stdout.strip())
        logger.debug("sssctl stderr:\n%s", result.stderr.strip())

        return "pam_acct_mgmt: Success" in result.stderr

    except Exception as e:
        logger.error("Failed HBAC check for user=%s service=%s: %s", user, service, e)
        return False

def check_access(user: str, service: str, rule_config: dict) -> bool:
    """
    Основная функция проверки:
    - берёт имя правила из конфигурации
    - проверяет, разрешён ли сервис
    - вызывает sssctl
    """
    expected_services = rule_config.get("services", {})
    if not expected_services.get(service, False):
        logger.info("Access denied: service '%s' not allowed by config", service)
        return False

    return check_hbac_access(user, service)