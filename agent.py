import socket
import requests
import psutil
import time

SERVER = "http://SERVER_IP:8000"

hostname = socket.gethostname()
ip = socket.gethostbyname(hostname)

def send_heartbeat():

    data = {
        "hostname": hostname,
        "ip": ip
    }

    requests.post(
        f"{SERVER}/heartbeat",
        json=data
    )

def collect_process_logs():

    logs = []

    for proc in psutil.process_iter():

        try:

            name = proc.name()

            logs.append({
                "category": "process",
                "content": f"Running process: {name}"
            })

        except:
            pass

    return logs

def collect_network_logs():

    logs = []

    for conn in psutil.net_connections():

        try:

            logs.append({
                "category": "network",
                "content": str(conn)
            })

        except:
            pass

    return logs

def send_logs(logs):

    data = {
        "hostname": hostname,
        "logs": logs
    }

    requests.post(
        f"{SERVER}/logs",
        json=data
    )

while True:

    try:

        send_heartbeat()

        logs = []

        logs.extend(collect_process_logs())
        logs.extend(collect_network_logs())

        send_logs(logs)

    except Exception as e:
        print(e)

    time.sleep(30)
