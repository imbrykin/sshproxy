import logging
from logging.handlers import RotatingFileHandler
import os

LOG_DIR = "/var/log/ssh-proxy"
LOG_FILE = os.path.join(LOG_DIR, "sshproxy.log")


def setup_logging():
    os.makedirs(LOG_DIR, exist_ok=True)

    log_level_str = os.getenv("LOGLEVEL", "INFO").upper()
    log_level = getattr(logging, log_level_str, logging.INFO)

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    handler = RotatingFileHandler(LOG_FILE, maxBytes=5_000_000, backupCount=5)
    handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.addHandler(handler)
    root_logger.addHandler(console_handler)
