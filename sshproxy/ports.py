import os
import time
import socket
import random
import logging

logger = logging.getLogger(__name__)

PORTS_FILE = "/etc/sshproxy/ports.txt"
TTL_SECONDS = 3600


def read_used_ports():
    used_ports = set()
    now = time.time()
    valid_lines = []

    if os.path.exists(PORTS_FILE):
        with open(PORTS_FILE, "r") as f:
            for line in f:
                parts = line.strip().split(";")
                if len(parts) == 5:
                    try:
                        timestamp = float(parts[3])
                        pid = int(parts[4])
                        if os.path.exists(f"/proc/{pid}") or (now - timestamp < TTL_SECONDS):
                            used_ports.add(int(parts[2]))
                            valid_lines.append(line.strip())
                    except (ValueError, IndexError):
                        continue

    try:
        with open(PORTS_FILE, "w") as f:
            for line in valid_lines:
                f.write(line + "\n")
    except Exception as e:
        logger.warning("Could not rewrite ports file: %s", e)

    return used_ports


def get_free_port(start=2222, end=65535):
    used_ports = read_used_ports()
    for _ in range(200):
        port = random.randint(start, end)
        if port in used_ports:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("0.0.0.0", port))
                return port
            except OSError:
                continue
    raise RuntimeError("No free port available in range")


def log_assigned_port(user: str, port: int, pid: int):
    try:
        os.makedirs(os.path.dirname(PORTS_FILE), exist_ok=True)
        with open(PORTS_FILE, "a") as f:
            f.write(f";{user};{port};{time.time()};{pid}\n")
        logger.info("Assigned port %d to %s [PID %d]", port, user, pid)
    except Exception as e:
        logger.warning("Could not write to ports file: %s", e)