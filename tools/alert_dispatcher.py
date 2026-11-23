#!/usr/bin/env python3
"""
alert_dispatcher.py — Real-time Webhook Dispatcher for Moros AI (Telegram, Discord, Slack).
"""

import json
import logging
import os
import urllib.request
from typing import Any, Dict, Optional

logger = logging.getLogger("alert-dispatcher")


class AlertDispatcher:
    def __init__(self):
        self.discord_url = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
        self.telegram_bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
        self.telegram_chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
        self.slack_url = os.environ.get("SLACK_WEBHOOK_URL", "").strip()

    def is_configured(self) -> bool:
        return bool(self.discord_url or (self.telegram_bot_token and self.telegram_chat_id) or self.slack_url)

    def send_alert(self, title: str, message: str, severity: str = "INFO", fields: Optional[Dict[str, str]] = None):
        """Dispatch an alert to all configured channels."""
        if not self.is_configured():
            return

        # 1. Discord Webhook
        if self.discord_url:
            self._send_discord(title, message, severity, fields)

        # 2. Telegram Bot
        if self.telegram_bot_token and self.telegram_chat_id:
            self._send_telegram(title, message, severity, fields)

        # 3. Slack Webhook
        if self.slack_url:
            self._send_slack(title, message, severity, fields)

    def _send_discord(self, title: str, message: str, severity: str, fields: Optional[Dict[str, str]]):
        colors = {
            "CRITICAL": 0xFF0000,
            "HIGH": 0xFF4500,
            "MEDIUM": 0xFFA500,
            "LOW": 0x3498DB,
            "INFO": 0x2ECC71,
        }
        color = colors.get(severity.upper(), 0x3498DB)
        discord_fields = [{"name": k, "value": str(v)[:250], "inline": True} for k, v in (fields or {}).items()]

        payload = {
            "username": "Moros AI Sentinel",
            "embeds": [{
                "title": f"🚨 [{severity.upper()}] {title}",
                "description": message[:1800],
                "color": color,
                "fields": discord_fields[:10],
                "footer": {"text": "Moros AI Autonomous Security Agent"}
            }]
        }
        try:
            req = urllib.request.Request(
                self.discord_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "MorosAI/1.0"}
            )
            urllib.request.urlopen(req, timeout=10)
        except Exception as e:
            logger.warning(f"Failed to deliver Discord alert: {e}")

    def _send_telegram(self, title: str, message: str, severity: str, fields: Optional[Dict[str, str]]):
        url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
        text = f"🚨 *[Moros AI - {severity.upper()}]* {title}\n\n{message}\n"
        if fields:
            for k, v in fields.items():
                text += f"\n• *{k}:* `{str(v)[:150]}`"

        payload = {
            "chat_id": self.telegram_chat_id,
            "text": text,
            "parse_mode": "Markdown"
        }
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "MorosAI/1.0"}
            )
            urllib.request.urlopen(req, timeout=10)
        except Exception as e:
            logger.warning(f"Failed to deliver Telegram alert: {e}")

    def _send_slack(self, title: str, message: str, severity: str, fields: Optional[Dict[str, str]]):
        payload = {
            "text": f"🚨 *[{severity.upper()}] {title}*\n{message}",
        }
        try:
            req = urllib.request.Request(
                self.slack_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "MorosAI/1.0"}
            )
            urllib.request.urlopen(req, timeout=10)
        except Exception as e:
            logger.warning(f"Failed to deliver Slack alert: {e}")
