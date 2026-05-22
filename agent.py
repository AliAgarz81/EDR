import socket
import requests
import time
import win32evtlog

SERVER = "http://192.168.0.197:8000"

hostname = socket.gethostname()


def get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_addr = s.getsockname()[0]
        s.close()
        return ip_addr
    except Exception:
        return socket.gethostbyname(hostname)


ip = get_ip()


def send_heartbeat():
    data = {
        "hostname": hostname,
        "ip": ip
    }

    try:
        print("[*] Heartbeat göndərilir...")

        response = requests.post(
            f"{SERVER}/heartbeat",
            json=data,
            timeout=5
        )

        if response.status_code == 200:
            print("[+] Heartbeat uğurla göndərildi.")
        else:
            print(f"[-] Heartbeat response code: {response.status_code}")

    except Exception as e:
        print(f"[-] Heartbeat göndərilə bilmədi: {e}")


def collect_windows_event_logs(log_type="Security", max_records=50):
    logs = []

    print("=" * 80)
    print(f"[*] Windows '{log_type}' loqları oxunur...")
    print("=" * 80)

    try:
        hand = win32evtlog.OpenEventLog(None, log_type)

        flags = (
            win32evtlog.EVENTLOG_BACKWARDS_READ |
            win32evtlog.EVENTLOG_SEQUENTIAL_READ
        )

        events = win32evtlog.ReadEventLog(hand, flags, 0)

        count = 0

        while events and count < max_records:

            for event in events:

                event_id = event.EventID & 0xFFFF

                raw_strings = event.StringInserts

                data_content = (
                    " | ".join(raw_strings)
                    if raw_strings
                    else "No dynamic data"
                )

                full_raw_log = (
                    f"Time: {event.TimeGenerated} | "
                    f"Source: {event.SourceName} | "
                    f"EventID: {event_id} | "
                    f"Type: {event.EventType} | "
                    f"RawData: {data_content}"
                )

                # PRINT LOG
                print("=" * 80)
                print(f"[{log_type}] Yeni Log")
                print(f"Time       : {event.TimeGenerated}")
                print(f"Source     : {event.SourceName}")
                print(f"Event ID   : {event_id}")
                print(f"Event Type : {event.EventType}")
                print(f"Data       : {data_content}")
                print("=" * 80)

                logs.append({
                    "category": log_type.lower(),
                    "content": full_raw_log
                })

                count += 1

                if count >= max_records:
                    break

            events = win32evtlog.ReadEventLog(hand, flags, 0)

        win32evtlog.CloseEventLog(hand)

        print(f"[+] '{log_type}' logundan {count} ədəd log oxundu.")

    except Exception as e:
        print(f"[-] '{log_type}' logları oxunarkən xəta: {e}")

        logs.append({
            "category": "error",
            "content": f"Event Log error: {str(e)}"
        })

    return logs


def send_logs(logs):
    data = {
        "hostname": hostname,
        "logs": logs
    }

    try:
        print(f"[*] {len(logs)} ədəd log serverə göndərilir...")

        response = requests.post(
            f"{SERVER}/logs",
            json=data,
            timeout=10
        )

        if response.status_code == 200:
            print("[+] Loqlar server tərəfindən qəbul edildi.")
        else:
            print(f"[-] Server response code: {response.status_code}")

    except Exception as e:
        print(f"[-] Loqlar göndərilə bilmədi: {e}")


# ---------------- MAIN LOOP ----------------

if __name__ == "__main__":

    print("=" * 80)
    print("[!] NexGuard EDR Agent Started")
    print(f"[!] Hostname : {hostname}")
    print(f"[!] IP        : {ip}")
    print(f"[!] Server    : {SERVER}")
    print("=" * 80)

    while True:

        # 1. Heartbeat
        send_heartbeat()

        # 2. Collect Logs
        logs = []

        logs.extend(
            collect_windows_event_logs(
                "Security",
                max_records=30
            )
        )

        logs.extend(
            collect_windows_event_logs(
                "System",
                max_records=20
            )
        )

        # 3. Send Logs
        if logs:
            send_logs(logs)
        else:
            print("[*] Göndəriləcək log yoxdur.")

        print("\n" + "-" * 80)
        print("[*] Dövr tamamlandı. 30 saniyə gözlənilir...")
        print("-" * 80 + "\n")

        time.sleep(30)
