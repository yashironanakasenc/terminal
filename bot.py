#!/usr/bin/env python3
# 🎉🔥 Public Command Bot — Multi-User GH Edition 🔥🎉
# 🧳 Each user gets a jailed workspace
# 🐍 Node/Python supported
# 🚫 Dangerous commands + GUI/TUI blocked
# 🖥️ Hard-coded BOT_TOKEN for local VPS use
# 🔒 Fully supports multiple users with per-user GH isolation

import os
import shlex
import subprocess
import tempfile
from pathlib import Path
from telegram import Update
from telegram.ext import ApplicationBuilder, MessageHandler, CommandHandler, ContextTypes, filters

# ================== CONFIG ==================
BOT_TOKEN = "7361661359:AAGI9A56aal_GQBjlxpK7jHoL2lTg_0rYaM"
SESSION_BASE = Path(tempfile.gettempdir()) / "tg_public_sessions_final"
SESSION_BASE.mkdir(parents=True, exist_ok=True)

# ================== BANNED COMMANDS ==================
BANNED = {
    # 🚫 Dangerous system commands
    "passwd", "sudo", "su", "reboot", "shutdown", "poweroff",
    "mkfs", "dd", "htop", "systemctl", "chown", "mount", "umount",
    "iptables", "docker", "podman", "ssh", "scp", "rsync",
    "nc", "netcat", "nmap", "pkexec",

    # 🚫 GUI / TUI / interactive
    "nano", "vi", "vim", "less", "more", "top", "man", "mc",
    "dialog", "whiptail", "fzf", "lynx"
}

# Disallowed metacharacters
DISALLOWED = {"✓"}

CMD_TIMEOUT = 25
CHUNK = 3800

# ================== HELPERS ==================
def get_user_dir(user_id: int) -> Path:
    """Return jailed workspace for user."""
    p = SESSION_BASE / str(user_id)
    p.mkdir(parents=True, exist_ok=True)
    return p

def is_inside_jail(base: Path, target: Path) -> bool:
    """Ensure target directory is inside user's workspace."""
    try:
        return str(target.resolve()).startswith(str(base.resolve()))
    except Exception:
        return False

def short_path(base: Path, target: Path) -> str:
    """Pretty path relative to base."""
    try:
        rel = target.relative_to(base)
        return str(rel) if str(rel) != "." else "workspace"
    except ValueError:
        return target.name or "workspace"

def has_disallowed_chars(cmd: str) -> (bool, str):
    for s in DISALLOWED:
        if s in cmd:
            return True, f"Symbol not allowed: {s} 🚫"
    return False, ""

import re

def contains_banned(cmd: str) -> (bool, str):
    """
    Existing banned-command checks PLUS more careful detection for
    kill/pkill/killall/xargs patterns that can kill the whole system.
    """
    # Basic split by pipe already used upstream; keep the same segmentation logic
    segments = [seg.strip() for seg in cmd.split("|")]
    if not segments:
        return True, "Empty command 😕"

    for seg in segments:
        if not seg:
            return True, "Empty command segment 😕"
        try:
            tokens = shlex.split(seg)
        except Exception:
            return True, "Can't parse command 😵"

        if not tokens:
            return True, "No valid command 🤨"

        base = os.path.basename(tokens[0]).lower()

        # 1) direct banned binaries (add any more names here)
        DIRECT_BANNED = {
            "passwd", "sudo", "su", "reboot", "shutdown", "poweroff",
            "mkfs", "dd", "htop", "systemctl", "chown", "mount", "umount",
            "iptables", "docker", "podman", "ssh", "scp", "rsync",
            "nc", "netcat", "nmap", "pkexec", "shutdown", "halt", "telinit",
            "init", "skill"  # optional
        }
        if base in DIRECT_BANNED:
            return True, f"Command '{base}' is banned! ❌"

        # 2) Dangerous kill-related commands (smart checks)
        if base in ("kill", "pkill", "killall"):
            # Quick-ban for killall / pkill without further checks
            if base in ("killall", "pkill"):
                return True, f"Command '{base}' is disallowed here (system-wide kill). ❌"

            # Now handle 'kill' (more nuanced)
            # tokens example: ['kill', '-9', '-1'] or ['kill', '1234'] or ['kill', '-s', 'SIGKILL', '1']
            # Collect all non-option arguments (possible pids)
            pid_args = []
            i = 1
            while i < len(tokens):
                t = tokens[i]
                if t.startswith("-") and not re.match(r"^-?\d+$", t):
                    # option like -9 or -s SIGKILL etc.; but -9 is numeric option (signal)
                    # if it's -1 or -0 this is suspicious too; we'll consider numeric-looking tokens below
                    # handle -s SIGKILL (skip next token which is signal name) 
                    if t in ("-s", "--signal"):
                        # skip next token if exists (signal name)
                        i += 1
                    # otherwise it's an option; move on
                else:
                    pid_args.append(t)
                i += 1

            # If no explicit pid was given, but options exist e.g., "kill -9 -1" then tokens might include -1 as token
            # Let's search original segment for number-like arguments (including negative)
            nums = re.findall(r"(?:^|\s)(-?\d+)(?:\s|$)", seg)
            # Merge both lists
            for n in nums:
                pid_args.append(n)

            # Inspect pid_args for dangerous values
            for targ in pid_args:
                try:
                    v = int(targ)
                    if v <= 1 or v < 0:
                        # common dangerous values: -1, 0, 1 and negative in general
                        return True, f"Blocked dangerous kill target '{targ}' (would affect system PIDs). ❌"
                except Exception:
                    # targ might be a name (e.g., 'init' or 'systemd') — block those
                    lowered = targ.lower()
                    if lowered in ("init", "systemd", "systemctl", "root"):
                        return True, f"Blocked dangerous kill target '{targ}' (system process). ❌"

            # If still here, allow kill (user-kill). Note: you may optionally further restrict signals like SIGKILL
            # Disallow explicit SIGKILL usage targeting no concrete safe pid. E.g., 'kill -9' with no pid -> block
            # Check if command contains '-9' or 'SIGKILL' but no safe numeric pid > 1
            has_sigkill = bool(re.search(r"(^|\s)-9($|\s)|SIGKILL", seg, flags=re.IGNORECASE))
            safe_pid_present = any(re.match(r"^[2-9]\d*$", p) for p in pid_args if re.match(r"^-?\d+$", p))
            if has_sigkill and not safe_pid_present:
                return True, "SIGKILL usage without a safe numeric pid is blocked. ❌"

        # 3) xargs + kill pattern: "something | xargs kill" or "echo pid | xargs kill -9"
        if base == "xargs":
            # if xargs is used to call kill, check next token(s)
            # e.g., tokens = ['xargs', 'kill', '-9']
            if len(tokens) >= 2 and os.path.basename(tokens[1]).lower() == "kill":
                return True, "Use of xargs to call kill is blocked (could be system-wide). ❌"

        # 4) disallow piping obvious dangerous combos using keywords
        if re.search(r"\b(killall|pkill|kill)\b", seg) and re.search(r"\b(-1|^1$|init|systemd|root)\b", seg):
            return True, "Potentially dangerous kill pattern blocked. ❌"

    return False, ""

# ================== HANDLERS ==================
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    await update.message.reply_text(
        f"👋 Hello {user.first_name or 'friend'}!\n\n"
        "⚡ This is a *public VPS bot!* Each user runs in their own safe space.\n",
        parse_mode="Markdown"
    )

async def session_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    p = get_user_dir(user_id)
    await update.message.reply_text(f"🧭 Your session folder: `{p}`", parse_mode="Markdown")

async def ghlogin_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /ghlogin <token> safely."""
    user_id = update.effective_user.id
    args = context.args
    if not args:
        await update.message.reply_text("⚠️ Usage: /ghlogin YOUR_PERSONAL_ACCESS_TOKEN")
        return
    token = args[0].strip()
    if not token.startswith("gh") and not token.startswith("github_pat_"):
        await update.message.reply_text("⚠️ Invalid token format.")
        return

    base_dir = get_user_dir(user_id)
    gh_config = base_dir / ".gh"
    gh_data = base_dir / ".gh_data"
    gh_config.mkdir(parents=True, exist_ok=True)
    gh_data.mkdir(parents=True, exist_ok=True)

    try:
        proc = subprocess.run(
            "gh auth login --with-token",
            shell=True,
            input=token,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(base_dir),
            timeout=CMD_TIMEOUT,
            executable="/bin/bash",
            env={**os.environ, "GH_CONFIG_DIR": str(gh_config), "GH_DATA_DIR": str(gh_data)}
        )
        out = (proc.stdout or "").strip()
        err = (proc.stderr or "").strip()
        full = "\n".join([s for s in [out, err] if s]).strip()
        if not full:
            full = "✅ Logged in successfully (no output from GH CLI)"
    except Exception as e:
        full = f"❌ Error logging in: {e}"

    await update.message.reply_text(full)

async def command_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    text = update.message.text.strip()
    base_dir = get_user_dir(user_id)

    # Handle cd
    if text == "cd" or text.startswith("cd "):
        parts = text.split(maxsplit=1)
        target = parts[1].strip() if len(parts) > 1 else ""
        candidate = base_dir if not target or target in ("~", "/") else (base_dir / target)
        try:
            new_dir = candidate.resolve()
        except Exception:
            await update.message.reply_text("❌ Invalid directory.")
            return

        if not is_inside_jail(base_dir, new_dir):
            new_dir = base_dir

        if new_dir.exists() and new_dir.is_dir():
            (base_dir / ".cwd").write_text(str(new_dir))
            folder_name = short_path(base_dir, new_dir)
            await update.message.reply_text(f"📂 Changed directory to `{folder_name}`", parse_mode="Markdown")
        else:
            await update.message.reply_text("❌ Directory not found.")
        return

    # Determine cwd
    cwd = base_dir
    marker = base_dir / ".cwd"
    if marker.exists():
        try:
            saved = Path(marker.read_text().strip())
            if is_inside_jail(base_dir, saved):
                cwd = saved
        except Exception:
            pass

    # Safety checks
    badchar, reason = has_disallowed_chars(text)
    if badchar:
        await update.message.reply_text(f"⚠️ Not allowed: {reason}")
        return

    banned, reason = contains_banned(text)
    if banned:
        await update.message.reply_text(reason)
        return

    # GH env (persistent per user)
    gh_config = base_dir / ".gh"
    gh_data = base_dir / ".gh_data"
    gh_env = {**os.environ, "GH_CONFIG_DIR": str(gh_config), "GH_DATA_DIR": str(gh_data)}

    # Block interactive login
    if text.strip().lower().startswith("gh auth login") and "--with-token" not in text:
        await update.message.reply_text(
            "⚠️ Interactive `gh auth login` is not allowed. Use `/ghlogin YOUR_TOKEN` instead.",
            parse_mode="Markdown"
        )
        return

    # Prepend GH env if command starts with gh
    safe_text = text
    if text.strip().lower().startswith("gh "):
        safe_text = text

    # Execute
    try:
        proc = subprocess.run(
            safe_text,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(cwd),
            timeout=CMD_TIMEOUT,
            executable="/bin/bash",
            env=gh_env
        )
        out = (proc.stdout or "").strip()
        err = (proc.stderr or "").strip()
        full = "\n".join([s for s in [out, err] if s]).strip()
        if not full:
            full = "(No output) 🤫"
    except subprocess.TimeoutExpired:
        full = f"⏱️ Command timed out after {CMD_TIMEOUT} seconds!"
    except Exception as e:
        full = f"❗ Error executing command: {e}"

    # Send output safely
    for i in range(0, len(full), CHUNK):
        chunk = full[i:i + CHUNK]
        await update.message.reply_text(f"```\n{chunk}\n```", parse_mode="Markdown")

# ================== MAIN 🚀 ==================
def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("session", session_command))
    app.add_handler(CommandHandler("ghlogin", ghlogin_command))
    app.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), command_handler))
    print("🎈 Public Command Bot running... Safe, multi-user GH ready! 🔐")
    app.run_polling()

if __name__ == "__main__":
    main()
