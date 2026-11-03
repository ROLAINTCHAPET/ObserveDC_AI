"""Canaux de notification (D11). Socle sans Internet : SMS (passerelle ou modem) et
e-mail interne ; webhook de messagerie d'équipe en complément, jamais pour le niveau 3."""
import asyncio
import smtplib
from email.message import EmailMessage
from typing import Any, Protocol

import httpx

from shared.config import Settings

SMS_MAX = 300


class Channel(Protocol):
    name: str

    def recipients(self) -> list[str]: ...
    async def send(self, recipient: str, msg: dict[str, Any]) -> None: ...


def _split(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def short_text(msg: dict[str, Any]) -> str:
    level = f"N{msg['level']} " if msg.get("level") else ""
    text = f"[ObservIA {level}{msg['kind']}] {msg['subject']}"
    if msg.get("link"):
        text += f" {msg['link']}"
    return text[:SMS_MAX]


class EmailChannel:
    name = "email"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def recipients(self) -> list[str]:
        return _split(self.settings.email_recipients) if self.settings.smtp_host else []

    async def send(self, recipient: str, msg: dict[str, Any]) -> None:
        mail = EmailMessage()
        mail["From"] = self.settings.smtp_from
        mail["To"] = recipient
        mail["Subject"] = short_text({**msg, "link": None})
        mail.set_content("\n\n".join(filter(None, [msg["body"], msg.get("link")])))
        await asyncio.to_thread(self._send_sync, mail)

    def _send_sync(self, mail: EmailMessage) -> None:
        with smtplib.SMTP(self.settings.smtp_host, self.settings.smtp_port, timeout=10) as smtp:
            smtp.send_message(mail)


class SmsChannel:
    """Passerelle SMS générique HTTP ; adapter le corps à la passerelle réelle (phase 9)."""

    name = "sms"

    def __init__(self, settings: Settings, client: httpx.AsyncClient) -> None:
        self.settings = settings
        self.client = client

    def recipients(self) -> list[str]:
        return _split(self.settings.sms_recipients) if self.settings.sms_gateway_url else []

    async def send(self, recipient: str, msg: dict[str, Any]) -> None:
        resp = await self.client.post(self.settings.sms_gateway_url, json={"to": recipient, "text": short_text(msg)})
        resp.raise_for_status()


class WebhookChannel:
    name = "webhook"

    def __init__(self, settings: Settings, client: httpx.AsyncClient) -> None:
        self.settings = settings
        self.client = client

    def recipients(self) -> list[str]:
        return ["team"] if self.settings.team_webhook_url else []

    async def send(self, recipient: str, msg: dict[str, Any]) -> None:
        resp = await self.client.post(self.settings.team_webhook_url, json={"text": f"{short_text(msg)}\n{msg['body']}"})
        resp.raise_for_status()


# INTERNAL : la surveillance elle-même est aveugle (règle en échec ou non évaluée, M10, M15)
URGENT_KINDS = {"APPROVAL_REQUEST", "APPROVAL_REMINDER", "ESCALATION", "DEGRADED", "KILL_SWITCH", "INTERNAL"}


def route(msg: dict[str, Any]) -> list[str]:
    """Canaux par niveau d'urgence (FR-16). Niveau 3 : deux technologies indépendantes."""
    if msg.get("level") == 3 or msg["kind"] in URGENT_KINDS:
        return ["sms", "email"]
    return ["email", "webhook"]
