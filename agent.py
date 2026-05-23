import socket
import requests
import psutil
import time
import subprocess
import platform
import json
from datetime import datetime

SERVER = "http://20.10.0.84:8000"
AGENT_KEY = "edr-secret-key-2024"

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
HEADERS = {"X-Agent-Key": AGENT_KEY}

# --- Şübhəli Proseslər ---
SUSPICIOUS_PROCS = {
    'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
    'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe',
    'bitsadmin.exe', 'nc.exe', 'ncat.exe', 'netcat.exe',
    'mimikatz.exe', 'procdump.exe', 'psexec.exe', 'wmic.exe',
    'at.exe', 'schtasks.exe', 'msiexec.exe',
}

# --- Şübhəli Argumentlər ---
SUSPICIOUS_ARGS = [
    '-enc', '-encodedcommand', 'bypass', '-nop', '-noprofile',
    'invoke-expression', 'iex(', 'downloadstring', 'webclient',
    'frombase64', 'invoke-mimikatz', 'invoke-shellcode',
    '-windowstyle hidden', '/c powershell', 'hidden',
]

# --- Şübhəli Portlar ---
SUSPICIOUS_PORTS = {4444, 4445, 1337, 31337, 8888, 9999, 6666, 2222, 5555, 7777}

prev_pids = set()
prev_connections = set()

def get_system_info():
    try:
        boot_ts = psutil.boot_time()
        uptime_sec = int(time.time() - boot_ts)
        days = uptime_sec // 86400
        hours = (uptime_sec % 86400) // 3600
        mins = (uptime_sec % 3600) // 60
        uptime_str = f"{days}d {hours}h {mins}m" if days else f"{hours}h {mins}m"

        users = psutil.users()
        active_user = users[0].name.split("\\")[-1] if users else "Unknown"
        login_time = datetime.fromtimestamp(users[0].started).strftime("%Y-%m-%d %H:%M:%S") if users else "Unknown"

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
    procs = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status', 'username']):
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
    global prev_pids, prev_connections
    logs = []

    # ============================================================
    # 1. BÜTÜN PROSESLƏRİN MONİTORİNQİ (HƏM ADİ, HƏM ŞÜBHƏLİ)
    # ============================================================
    current_procs = {}
    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username', 'status', 'exe']):
        try:
            current_procs[proc.pid] = proc.info
        except Exception:
            pass

    current_pids = set(current_procs.keys())
    new_pids = current_pids - prev_pids

    for pid in new_pids:
        info = current_procs.get(pid, {})
        raw_name = info.get('name') or 'unknown'
        name_lower = raw_name.lower()
        cmdline_list = info.get('cmdline') or []
        cmdline = ' '.join(cmdline_list)
        username = (info.get('username') or '').split('\\')[-1]

        # Şübhə məntiqi (Aşkarlama hələ də işləyir)
        is_sus_name = name_lower in SUSPICIOUS_PROCS
        has_sus_arg = any(arg in cmdline.lower() for arg in SUSPICIOUS_ARGS)

        # Defolt olaraq hər bir yeni proses info səviyyəsində göndərilir
        severity = "info"
        is_suspicious = "false"

        if has_sus_arg:
            severity = "critical"
            is_suspicious = "true"
        elif is_sus_name:
            severity = "warning"
            is_suspicious = "true"

        raw_log = f"PROCESS_START: PID={pid} | Name={raw_name} | User={username} | Status={info.get('status')} | Exe={info.get('exe')} | Cmd={cmdline}"
        
        logs.append({
            "category": "process",
            "severity": severity,
            "content": raw_log,
            "fields": {
                "pid": pid,
                "process_name": raw_name,
                "username": username,
                "exe_path": info.get('exe') or "",
                "command_line": cmdline,
                "is_suspicious": is_suspicious
            }
        })
    prev_pids = current_pids

    # ============================================================
    # 2. BÜTÜN ŞƏBƏKƏ QOŞULMALARI (HƏM ADİ, HƏM ŞÜBHƏLİ)
    # ============================================================
    current_conns = {}
    ip_counts = {}
    try:
        for conn in psutil.net_connections(kind='inet'):
            if not conn.raddr:
                continue
            rip, rport = conn.raddr.ip, conn.raddr.port
            lip, lport = conn.laddr.ip, conn.laddr.port
            proto = "TCP" if getattr(conn, 'type', 1) == 1 else "UDP"
            status = getattr(conn, 'status', 'NONE')

            key = (rip, rport, lip, lport, proto, status, conn.pid)
            current_conns[key] = current_conns.get(key, 0) + 1
            ip_counts[rip] = ip_counts.get(rip, 0) + 1
    except Exception as e:
        print(f"[WARN] net_connections: {e}")

    LOCAL_PREFIXES = ('127.', '::1', '0.', '169.254.')

    # DDoS/Flood aşkarlama xəbərdarlığı (Həddi aşanda kritik loq əlavə edir)
    for rip, count in ip_counts.items():
        if any(rip.startswith(p) for p in LOCAL_PREFIXES): continue
        if count >= 10:
            sev = "critical" if count >= 20 else "warning"
            logs.append({
                "category": "network", "severity": sev,
                "content": f"NETWORK_FLOOD: Connection count alert from Remote IP {rip} | Total Connections: {count}",
                "fields": {"remote_ip": rip, "connection_count": count, "alert_type": "DDoS/Flood_Suspect", "is_suspicious": "true"}
            })

    # Hər bir yeni şəbəkə bağlantısını SIEM-ə ötürürük
    new_conns = set(current_conns.keys()) - prev_connections
    for (rip, rport, lip, lport, proto, status, c_pid) in new_conns:
        if any(rip.startswith(p) for p in LOCAL_PREFIXES): continue
        
        is_sus_port = rport in SUSPICIOUS_PORTS
        severity = "warning" if is_sus_port else "info"
        is_suspicious = "true" if is_sus_port else "false"
        
        p_name = "Unknown"
        if c_pid:
            try: p_name = psutil.Process(c_pid).name()
            except: pass

        raw_log = f"NET_CONN: Proto={proto} | Local={lip}:{lport} | Remote={rip}:{rport} | Status={status} | PID={c_pid} ({p_name})"
        
        logs.append({
            "category": "network", "severity": severity,
            "content": raw_log,
            "fields": {
                "protocol": proto, "remote_ip": rip, "remote_port": rport,
                "local_ip": lip, "local_port": lport, "status": status,
                "pid": c_pid, "process_name": p_name, "is_suspicious": is_suspicious
            }
        })
    prev_connections = set(current_conns.keys())

    # ============================================================
    # 3. WINDOWS AUDIT VƏ EVENT LOGS (GENİŞLƏNDİRİLMİŞ EVENT ID-LƏR)
    # ============================================================
    _collect_windows_events(logs)

    return logs

def _run_wevtutil(log_name, query, max_events=15):
    try:
        result = subprocess.run(
            ['wevtutil', 'qe', log_name, f'/q:{query}', '/f:text', f'/c:{max_events}', '/rd:true'],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout
    except:
        return ""

def _collect_windows_events(logs):
    # Security: Uğurlu (4624), Uğursuz (4625) girişlər və Log-out (4634) hadisələri
    q_sec = '*[System[(EventID=4624 or EventID=4625 or EventID=4634) and TimeCreated[timediff(@SystemTime) <= 120000]]]'
    sec_text = _run_wevtutil('Security', q_sec, max_events=25)
    if sec_text:
        _parse_and_add_wevt(sec_text, "security", logs)

    # System: Yeni Servis Quraşdırılması (7045 - Persistence üçün kritikdir)
    q_sys = '*[System[EventID=7045 and TimeCreated[timediff(@SystemTime) <= 120000]]]'
    sys_text = _run_wevtutil('System', q_sys, max_events=10)
    if sys_text:
        _parse_and_add_wevt(sys_text, "system", logs)

    # PowerShell: ScriptBlock icraları (4104 - Kod analizi üçün)
    q_ps = '*[System[EventID=4104 and TimeCreated[timediff(@SystemTime) <= 120000]]]'
    ps_text = _run_wevtutil('Microsoft-Windows-PowerShell/Operational', q_ps, max_events=10)
    if ps_text:
        _parse_and_add_wevt(ps_text, "security", logs)

def _parse_and_add_wevt(text, cat, logs):
    events = text.split("\n\n")
    for ev in events:
        if not ev.strip(): continue
        lines = ev.split("\n")
        
        eid = "Unknown"
        source = "Unknown"
        raw_accumulated = []
        fields = {}

        for l in lines:
            l_strip = l.strip()
            if not l_strip: continue
            raw_accumulated.append(l_strip)
            
            if l_strip.startswith("Event ID:"): eid = l_strip.split(":")[-1].strip()
            elif l_strip.startswith("Source:"): source = l_strip.split(":")[-1].strip()
            elif ":" in l_strip:
                k, v = l_strip.split(":", 1)
                k_clean = k.strip().lower().replace(" ", "_")
                v_clean = v.strip()
                if v_clean and len(k_clean) < 30:
                    fields[k_clean] = v_clean

        if eid != "Unknown":
            # Şübhə səviyyəsini təyin edirik
            severity = "info"
            is_suspicious = "false"
            
            if eid in ("4625", "4104"):
                severity = "warning"
                is_suspicious = "true"
            elif eid == "7045":
                severity = "critical"
                is_suspicious = "true"

            logs.append({
                "category": cat,
                "severity": severity,
                "content": " || ".join(raw_accumulated[:15]), # İlk 15 mühüm sətir raw data kimi
                "fields": {
                    "event_id": eid,
                    "source": source,
                    "is_suspicious": is_suspicious,
                    **fields
                }
            })

def send_heartbeat(system_info):
    try: requests.post(f"{SERVER}/heartbeat", json={"hostname": hostname, "ip": ip, "system_info": system_info}, headers=HEADERS, timeout=5)
    except: pass

def send_logs(logs):
    if not logs: return
    try: requests.post(f"{SERVER}/logs", json={"hostname": hostname, "logs": logs}, headers=HEADERS, timeout=5)
    except: pass

def send_processes(processes):
    try: requests.post(f"{SERVER}/processes", json={"hostname": hostname, "processes": processes}, headers=HEADERS, timeout=5)
    except: pass

if __name__ == "__main__":
    print(f"[NexGuard Agent] Continuous Telemetry Logging Mode Active. Host: {hostname}")
    for _p in psutil.process_iter(['pid']):
        try: prev_pids.add(_p.pid)
        except: pass
        
    while True:
        try:
            sinfo = get_system_info()
            send_heartbeat(sinfo)
            logs = collect_smart_logs()
            send_logs(logs)
            send_processes(get_top_processes())
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Shipped {len(logs)} logs to SIEM database.")
        except Exception as e:
            print(f"[ERR] Main Loop: {e}")
        time.sleep(30)
