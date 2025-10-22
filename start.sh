#!/bin/bash
echo "🚀 Starting bot..."

# Create virtual environment if not exists
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies fresh
pip install --no-cache-dir -r requirements.txt

# Run bot
python3 bot.py
