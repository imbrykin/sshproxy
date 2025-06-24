from dotenv import load_dotenv
from sshproxy.cli import app
from sshproxy.logging_setup import setup_logging

# Загружаем переменные из .env до всего остального
load_dotenv()

setup_logging()

if __name__ == "__main__":
    app()