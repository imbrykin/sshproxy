import typer
from sshproxy.core import start_session
from sshproxy.ports import read_used_ports
import subprocess
import os
import signal
from datetime import datetime, timedelta

app = typer.Typer()


@app.command()
def conn(
    h: str = typer.Option(..., "-h", "--host", help="Hostname or IP address"),
    u: str = typer.Option(..., "-u", "--user", help="Username"),
    t: int = typer.Option(0, "-t", "--type", help="Mode: 0=SSH, 1=SFTP"),
    p: int = typer.Option(22, "-p", "--port", help="SSH port")
):
    """
    Start an SSH or SFTP session using FreeIPA authorization.
    """
    start_session(host=h, user=u, mode=t, port=p)

    # Log hostname to /etc/sshproxy/hostnames.txt with current PID and timestamp
    try:
        hostname_log = "/var/log/ssh-proxy/hostnames.txt"
        pid = os.getpid()
        timestamp = datetime.utcnow().isoformat()
        with open(hostname_log, "a") as f:
            f.write(f"{h};{pid};{timestamp}\n")
    except Exception as e:
        typer.echo(f"[WARN] Failed to log hostname mapping: {e}")


@app.command()
def cleanup():
    """
    Clean up stale or expired ports and hostname mappings.
    """
    used_ports = read_used_ports()
    typer.echo(f"[INFO] Found {len(used_ports)} valid port entries")

    # Clean hostnames.txt (older than 1 hour)
    host_file = "/var/log/ssh-proxy/hostnames.txt"
    if os.path.exists(host_file):
        threshold = datetime.utcnow() - timedelta(hours=1)
        valid_lines = []
        with open(host_file) as f:
            for line in f:
                parts = line.strip().split(";")
                if len(parts) == 3:
                    try:
                        ts = datetime.fromisoformat(parts[2])
                        if ts > threshold:
                            valid_lines.append(line.strip())
                    except Exception:
                        continue
        with open(host_file, "w") as f:
            for line in valid_lines:
                f.write(line + "\n")
        typer.echo(f"[INFO] Cleaned hostnames.txt, {len(valid_lines)} recent entries retained")


@app.command()
def view_logs(user: str = typer.Option(None, help="Filter by user")):
    """
    View recent logs from sshproxy log file.
    """
    log_path = "/var/log/ssh-proxy/sshproxy.log"
    if not os.path.exists(log_path):
        typer.echo("Log file not found.")
        raise typer.Exit(1)

    try:
        cmd = ["tail", "-n", "50", log_path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        lines = result.stdout.strip().splitlines()
        if user:
            lines = [line for line in lines if user in line]
        for line in lines:
            typer.echo(line)
    except Exception as e:
        typer.echo(f"Error reading log: {e}")


@app.command()
def sessions():
    """
    Show currently active proxy sessions from ports.txt.
    """
    ports_file = "/etc/sshproxy/ports.txt"
    if not os.path.exists(ports_file):
        typer.echo("No active session data available.")
        return

    with open(ports_file) as f:
        for line in f:
            parts = line.strip().split(";")
            if len(parts) == 5:
                _, user, port, ts, pid = parts
                typer.echo(f"User: {user}, Port: {port}, PID: {pid}, Timestamp: {ts}")


@app.command()
def kill_session(pid: int = typer.Argument(..., help="PID of the session to terminate")):
    """
    Kill a running proxy session by its PID.
    """
    try:
        os.kill(pid, signal.SIGTERM)
        typer.echo(f"Sent SIGTERM to PID {pid}.")
    except ProcessLookupError:
        typer.echo(f"No such process with PID {pid}.")
    except PermissionError:
        typer.echo(f"Permission denied to terminate PID {pid}.")
    except Exception as e:
        typer.echo(f"Error terminating PID {pid}: {e}")


@app.command()
def kill_user_sessions(user: str = typer.Argument(..., help="Username whose sessions to terminate")):
    """
    Kill all active proxy sessions for a specific user.
    """
    ports_file = "/etc/sshproxy/ports.txt"
    if not os.path.exists(ports_file):
        typer.echo("No session data available.")
        raise typer.Exit(1)

    killed = 0
    with open(ports_file) as f:
        for line in f:
            parts = line.strip().split(";")
            if len(parts) == 5 and parts[1] == user:
                try:
                    pid = int(parts[4])
                    os.kill(pid, signal.SIGTERM)
                    typer.echo(f"Killed session PID {pid} for user {user}")
                    killed += 1
                except ProcessLookupError:
                    typer.echo(f"PID {pid} not found.")
                except PermissionError:
                    typer.echo(f"No permission to kill PID {pid}.")
                except Exception as e:
                    typer.echo(f"Failed to kill PID {pid}: {e}")

    typer.echo(f"Total sessions killed for {user}: {killed}")


@app.command()
def kill_host_sessions(host: str = typer.Argument(..., help="Hostname whose sessions to terminate")):
    """
    Kill all active proxy sessions for a specific host.
    """
    host_file = "/var/log/ssh-proxy/hostnames.txt"
    if not os.path.exists(host_file):
        typer.echo("No hostname session mapping available.")
        raise typer.Exit(1)

    pids_to_kill = []
    with open(host_file) as f:
        for line in f:
            parts = line.strip().split(";")
            if len(parts) >= 2:
                h, pid = parts[0], parts[1]
                if h == host:
                    try:
                        pids_to_kill.append(int(pid))
                    except ValueError:
                        continue

    killed = 0
    for pid in pids_to_kill:
        try:
            os.kill(pid, signal.SIGTERM)
            typer.echo(f"Killed session PID {pid} for host {host}")
            killed += 1
        except ProcessLookupError:
            typer.echo(f"PID {pid} not found.")
        except PermissionError:
            typer.echo(f"No permission to kill PID {pid}.")
        except Exception as e:
            typer.echo(f"Failed to kill PID {pid}: {e}")

    typer.echo(f"Total sessions killed for host {host}: {killed}")