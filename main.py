from sshproxy.cli import app
from sshproxy.logging_setup import setup_logging

setup_logging()

if __name__ == "__main__":
    app()