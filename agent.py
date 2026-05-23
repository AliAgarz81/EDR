import socket
import requests
import psutil
import time
import subprocess
import platform
import json
from datetime import datetime

SERVER = "http://192.168.0.197:8000"
AGENT_KEY = "edr-secret-key-2024"

hostname = socket.gethostname()
ip = socket.gethostbyname(hostname)

HEADERS = {"X-Agent-Key": AGENT_KEY}

# --- Şübhəli proses adları ---
SUSPICIOUS_PROCS = {
    'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
    'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe',
    'bitsadmin.exe', 'nc.exe', 'ncat.exe', 'netcat.exe',
    'mimikatz.exe', 'procdump.exe', 'psexec.exe', 'wmic.exe',
    'at.exe', 'schtasks.exe', 'msiexec.exe',
}

# --- Şübhəli komanda argumentləri ---
SUSPICIOUS_ARGS = [
    '-enc', '-encodedcommand', 'bypass', '-nop', '-noprofile',
    'invoke-expression', 'iex(', 'downloadstring', 'webclient',
    'frombase64', 'invoke-mimikatz', 'invoke-shellcode',
    '-windowstyle hidden', '/c powershell', 'hidden',
]

# --- Şübhəli portlar ---
SUSPICIOUS_PORTS = {4444, 4445, 1337, 31337, 8888, 9999, 6666, 2222, 5555, 7777}

# --- Flood zamanı sayılmaması üçün sistem prosesləri ---
NOISE_PROCS = {
    'svchost.exe', 'conhost.exe', 'dllhost.exe', 'backgroundtaskhost.exe',
    'taskhostw.exe', 'runtimebroker.exe', 'searchindexer.exe',
    'wuauclt.exe', 'system', 'registry', 'smss.exe', 'csrss.exe',
    'winlogon.exe', 'lsass.exe', 'spoolsv.exe', 'audiodg.exe',
}

# --- State tracking ---
prev_pids = set()
prev_connections = set()


def get_system_info():
    """CPU, RAM, Disk, User, Uptime məlumatlarını toplayır."""
    try:
        boot_ts = psutil.boot_time()
        uptime_sec = int(time.time() - boot_ts)
        days = uptime_sec // 86400
        hours = (uptime_sec % 86400) // 3600
        mins = (uptime_sec % 3600) // 60
        uptime_str = f"{days}d {hours}h {mins}m" if days else f"{hours}h {mins}m"

        users = psutil.users()
        active_user = users[0].name.split("\\")[-1] if users else "Unknown"
        login_time = (
            datetime.fromtimestamp(users[0].started).strftime("%Y-%m-%d %H:%M:%S")
            if users else "Unknown"
        )

        vm = psutil.virtual_memory()
        disk = psutil.disk_usage("/")

        return {
            "cpu_percent":  psutil.cpu_percent(interval=0.5),
            "ram_percent":  vm.percent,
            "ram_used_gb":  round(vm.used  / 1024 ** 3, 2),
            "ram_total_gb": round(vm.total / 1024 ** 3, 2),
            "disk_percent":  disk.percent,
            "disk_used_gb":  round(disk.used  / 1024 ** 3, 2),
            "disk_total_gb": round(disk.total / 1024 ** 3, 2),
            "uptime":       uptime_str,
            "boot_time":    datetime.fromtimestamp(boot_ts).strftime("%Y-%m-%d %H:%M:%S"),
            "active_user":  active_user,
            "login_time":   login_time,
            "os":           f"{platform.system()} {platform.release()}",
            "architecture": platform.machine(),
        }
    except Exception as e:
        print(f"[WARN] get_system_info: {e}")
        return {}


def get_top_processes():
    """CPU-ya görə üst 50 prosesi qaytarır."""
    procs = []
    for proc in psutil.process_iter(
        ['pid', 'name', 'cpu_percent', 'memory_percent', 'status', 'username']
    ):
        try:
            i = proc.info
            procs.append({
                "pid":    i['pid'],
                "name":   i['name'] or "unknown",
                "cpu":    round(i.get('cpu_percent') or 0, 2),
                "memory": round(i.get('memory_percent') or 0, 2),
                "status": i.get('status', ''),
                "user":   (i.get('username') or '').split('\\')[-1],
            })
        except Exception:
            pass
    procs.sort(key=lambda x: (x['cpu'], x['memory']), reverse=True)
    return procs[:50]


def collect_smart_logs():
    """Yalnız mənalı, strukturlu log-ları toplayır."""
    global prev_pids, prev_connections
    logs = []

    # ============================================================
    # 1. PROSES MONİTORİNQİ — yalnız yeni/şübhəli proseslər
    # ============================================================
    current_procs = {}
    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
        try:
            current_procs[proc.pid] = proc.info
        except Exception:
            pass

    current_pids = set(current_procs.keys())
    new_pids = current_pids - prev_pids

    for pid in new_pids:
        info = current_procs.get(pid, {})
        raw_name = (info.get('name') or 'unknown')
        name_lower = raw_name.lower()

        cmdline_list = info.get('cmdline') or []
        cmdline = ' '.join(cmdline_list).lower()

        is_sus_name = name_lower in SUSPICIOUS_PROCS
        has_sus_arg = any(arg in cmdline for arg in SUSPICIOUS_ARGS)

        if is_sus_name or has_sus_arg:
            severity = "critical" if has_sus_arg else "warning"
            cmd_preview = ' '.join(cmdline_list)[:300] if cmdline_list else ""
            msg = f"Suspicious process started: {raw_name} (PID:{pid})"
            if cmd_preview:
                msg += f" | CMD: {cmd_preview}"
            logs.append({"category": "process", "severity": severity, "content": msg})
        elif prev_pids and name_lower not in NOISE_PROCS:
            # Yeni adi proses — yalnız ilk dəfə işlədildikdə qeyd et
            logs.append({
                "category": "process",
                "severity": "info",
                "content": f"New process started: {raw_name} (PID:{pid})",
            })

    prev_pids = current_pids

    # ============================================================
    # 2. ŞƏBƏKƏ MONİTORİNQİ — DDoS aşkarlanması, şübhəli portlar
    # ============================================================
    current_conns = {}
    ip_counts = {}

    try:
        for conn in psutil.net_connections(kind='inet'):
            if not conn.raddr:
                continue
            rip   = conn.raddr.ip
            rport = conn.raddr.port
            proto  = "TCP" if getattr(conn, 'type', 1) == 1 else "UDP"
            status = getattr(conn, 'status', '')

            key = (rip, rport, proto, status)
            current_conns[key] = current_conns.get(key, 0) + 1
            ip_counts[rip] = ip_counts.get(rip, 0) + 1
    except Exception as e:
        print(f"[WARN] net_connections: {e}")

    LOCAL_PREFIXES = ('127.', '::1', '0.', '169.254.')

    # DDoS / Flood aşkarlanması
    for rip, count in ip_counts.items():
        if any(rip.startswith(p) for p in LOCAL_PREFIXES):
            continue
        if count >= 20:
            logs.append({
                "category": "network", "severity": "critical",
                "content": f"POSSIBLE DDoS/FLOOD: {count} simultaneous connections → {rip}",
            })
        elif count >= 10:
            logs.append({
                "category": "network", "severity": "warning",
                "content": f"High connection count: {count} connections → {rip}",
            })

    # Yeni xarici bağlantılar
    new_conns = set(current_conns.keys()) - prev_connections
    for (rip, rport, proto, status) in new_conns:
        if any(rip.startswith(p) for p in LOCAL_PREFIXES):
            continue
        is_sus = rport in SUSPICIOUS_PORTS
        sev = "warning" if is_sus else "info"
        content = f"New {proto} connection: → {rip}:{rport} [{status}]"
        if is_sus:
            content += "  ⚠️ SUSPICIOUS PORT!"
        logs.append({"category": "network", "severity": sev, "content": content})

    prev_connections = set(current_conns.keys())

    # ============================================================
    # 3. WINDOWS EVENT LOG — login/logout, PowerShell, servis
    # ============================================================
    _collect_security_events(logs)
    _collect_system_events(logs)

    return logs


def _run_wevtutil(log_name, query, max_events=20, timeout=8):
    """wevtutil ilə Windows Event Log-dan hadisələri oxuyur."""
    try:
        result = subprocess.run(
            ['wevtutil', 'qe', log_name, f'/q:{query}',
             '/f:text', f'/c:{max_events}', '/rd:true'],
            capture_output=True, text=True, timeout=timeout
        )
        return result.stdout
    except Exception:
        return ""


def _collect_security_events(logs):
    """Uğurlu/uğursuz login, logout hadisələrini toplayır."""
    query = ('*[System[(EventID=4624 or EventID=4625 or EventID=4634) '
             'and TimeCreated[timediff(@SystemTime) <= 120000]]]')
    text = _run_wevtutil('Security', query, max_events=30)
    if not text:
        return

    current_id = None
    accounts = []
    SKIP_ACCOUNTS = {'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', '-', '', 'ANONYMOUS LOGON'}

    for line in text.split('\n'):
        line = line.strip()
        if line.startswith('Event ID:'):
            if current_id and accounts:
                _emit_login_event(current_id, accounts[-1], logs)
            current_id = line.split(':')[-1].strip()
            accounts = []
        elif 'Account Name:' in line:
            val = line.split('Account Name:')[-1].strip()
            if val and val not in SKIP_ACCOUNTS:
                accounts.append(val)

    if current_id and accounts:
        _emit_login_event(current_id, accounts[-1], logs)


def _emit_login_event(event_id, user, logs):
    if event_id == '4624':
        logs.append({"category": "security", "severity": "info",
                     "content": f"✅ Successful login: {user}"})
    elif event_id == '4625':
        logs.append({"category": "security", "severity": "warning",
                     "content": f"❌ Failed login attempt: {user}"})
    elif event_id == '4634':
        logs.append({"category": "security", "severity": "info",
                     "content": f"🚪 User logged out: {user}"})


def _collect_system_events(logs):
    """Yeni servis quraşdırılması, PowerShell ScriptBlock."""
    # Yeni servis (malware persistence)
    q7045 = '*[System[EventID=7045 and TimeCreated[timediff(@SystemTime) <= 120000]]]'
    if _run_wevtutil('System', q7045, max_events=5):
        logs.append({
            "category": "system", "severity": "warning",
            "content": "⚠️ New Windows service installed (Event 7045) — possible persistence!",
        })

    # PowerShell ScriptBlock (obfuscated code aşkarlanması)
    q4104 = '*[System[EventID=4104 and TimeCreated[timediff(@SystemTime) <= 120000]]]'
    ps_out = _run_wevtutil('Microsoft-Windows-PowerShell/Operational', q4104, max_events=5)
    if ps_out and 'ScriptBlock' in ps_out:
        logs.append({
            "category": "security", "severity": "warning",
            "content": "⚠️ PowerShell ScriptBlock execution detected (Event 4104)",
        })


# ================================================================
# GÖNDƏRMƏ FUNKSİYALARI
# ================================================================
def send_heartbeat(system_info):
    data = {"hostname": hostname, "ip": ip, "system_info": system_info}
    requests.post(f"{SERVER}/heartbeat", json=data, headers=HEADERS, timeout=10)


def send_logs(logs):
    if not logs:
        return
    requests.post(f"{SERVER}/logs",
                  json={"hostname": hostname, "logs": logs},
                  headers=HEADERS, timeout=10)


def send_processes(processes):
    requests.post(f"{SERVER}/processes",
                  json={"hostname": hostname, "processes": processes},
                  headers=HEADERS, timeout=10)


# ================================================================
# BAŞLANĞIC
# ================================================================
print(f"[EDR Agent] Starting → {hostname} ({ip})")
print(f"[EDR Agent] Server   → {SERVER}")

# İlk dəfə mövcud PID-ləri qeyd edirik ki, flood olmasm
for _p in psutil.process_iter(['pid']):
    try:
        prev_pids.add(_p.pid)
    except Exception:
        pass
print(f"[EDR Agent] Tracking {len(prev_pids)} existing processes")

# ================================================================
# ANA DÖVR
# ================================================================
while True:
    try:
        sinfo = get_system_info()
        send_heartbeat(sinfo)

        logs  = collect_smart_logs()
        send_logs(logs)

        procs = get_top_processes()
        send_processes(procs)

        ts = datetime.now().strftime('%H:%M:%S')
        print(f"[{ts}] Logs: {len(logs)} | CPU: {sinfo.get('cpu_percent', '?')}% "
              f"| RAM: {sinfo.get('ram_percent', '?')}%")

    except Exception as e:
        print(f"[ERROR] {e}")

    time.sleep(30)
