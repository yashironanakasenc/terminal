import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from telegram import Update
from telegram.ext import ApplicationBuilder, MessageHandler, ContextTypes, filters

BOT_TOKEN = '7361661359:AAGI9A56aal_GQBjlxpK7jHoL2lTg_0rYaM'
ALLOWED_USER_ID = 5193826370

# Store user's current working directory
current_dir = os.path.expanduser("~")  # Default: home directory


async def handle_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global current_dir
    user_id = update.effective_user.id
    if user_id != ALLOWED_USER_ID:
        await update.message.reply_text("Unauthorized access.")
        return

    command = update.message.text.strip()

    # Handle "cd" commands
    if command.startswith("cd "):
        path = command[3:].strip()
        new_dir = os.path.abspath(os.path.join(current_dir, path))
        if os.path.isdir(new_dir):
            current_dir = new_dir
            await update.message.reply_text(f"Changed directory to: {current_dir}")
        else:
            await update.message.reply_text(f"No such directory: {new_dir}")
        return

    # Run shell commands
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            cwd=current_dir,
            timeout=30
        )
        output = (result.stdout + result.stderr).strip()
        if not output:
            output = "(No output)"
    except Exception as e:
        output = f"Error: {e}"

    # Send output in chunks (to prevent Telegram limit)
    for i in range(0, len(output), 4000):
        await update.message.reply_text(output[i:i + 4000])


# Telegram app setup
app = ApplicationBuilder().token(BOT_TOKEN).build()
app.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), handle_command))


# ---------------------------
# Web server (for Render ping)
# ---------------------------
class PingHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"✅ Bot is alive")

def run_web():
    port = int(os.environ.get("PORT", 10000))
    server = HTTPServer(("0.0.0.0", port), PingHandler)
    print(f"🌐 Ping server started on port {port}")
    server.serve_forever()


if __name__ == '__main__':
    threading.Thread(target=run_web, daemon=True).start()
    print("🤖 Telegram bot running...")
    app.run_polling()
