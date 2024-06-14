import asyncio
import logging
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, SMTP
from email.parser import BytesParser
from email.policy import default
import aiohttp
import base64
import ssl

# Brevo API 配置
BREVO_API_KEY = '.....'
BREVO_API_URL = 'https://api.brevo.com/v3/smtp/email'

# 认证用户字典
AUTHORIZED_USERS = {
    "user1": "pass1"
}

# TLS证书路径
CERT_PATH = '/root/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/smtp.btc86.com/smtp.btc86.com.crt'
KEY_PATH = '/root/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/smtp.btc86.com/smtp.btc86.com.key'

class CustomSMTPHandler:
    async def handle_EHLO(self, server, session, envelope, hostname, responses):
        """Handle EHLO command."""
        session.extended_smtp = True
        print("EHLO received from:", hostname)
        responses.insert(0, '250-AUTH PLAIN')
        session.ehlo_received = True
        print("EHLO responses:", responses)
        return responses

    async def handle_STARTTLS(self, server, session, envelope):
        """Handle STARTTLS command."""
        print("Received STARTTLS command")
        await session.push('220 Ready to start TLS')
        context = load_ssl_context()
        transport = session.transport
        try:
            transport.start_tls(context, server_side=True)
            print("TLS handshake completed")
            session.require_tls = True
        except Exception as e:
            print(f"Error during TLS handshake: {e}")

    async def handle_AUTH(self, server, session, envelope, args):
        """Handle AUTH command as specified in the documentation."""
        print(f"AUTH received with args: {args}")
        if not session.ehlo_received:
            print("AUTH command received before EHLO")
            await session.push('503 Error: send EHLO first')
            return AuthResult(success=False)

        mechanism = args[0].upper() if args else ''
        auth_data = args[1] if len(args) > 1 else ''

        if mechanism == 'LOGIN':
            await session.push('334 VXNlcm5hbWU6')  # Username:
            username = base64.b64decode(await session.readline()).decode('utf-8')
            await session.push('334 UGFzc3dvcmQ6')  # Password:
            password = base64.b64decode(await session.readline()).decode('utf-8')
            return await self.check_credentials(session, username, password)
        elif mechanism == 'PLAIN':
            auth_str = base64.b64decode(auth_data).decode('utf-8')
            _, username, password = auth_str.split('\x00')
            return await self.check_credentials(session, username, password)
        else:
            print(f"Unsupported AUTH mechanism: {mechanism}")
            await session.push('504 Unrecognized authentication type')
            return AuthResult(success=False)

    async def auth_PLAIN(self, server, args):
        print("Received auth_PLAIN command")
        """Handle PLAIN authentication mechanism."""
        auth_str = base64.b64decode(args[0]).decode('utf-8')
        _, username, password = auth_str.split('\x00')
        if username in AUTHORIZED_USERS and AUTHORIZED_USERS[username] == password:
            print(f"Authentication successful for user: {username}")
            return AuthResult(success=True)
        else:
            print(f"Authentication failed for user: {username}")
            return AuthResult(success=False)

    async def auth_LOGIN(self, server, args):
        print("Received auth_LOGIN command")

    async def check_credentials(self, session, username, password):
        """Check credentials."""
        if username in AUTHORIZED_USERS and AUTHORIZED_USERS[username] == password:
            print(f"Authentication successful for user: {username}")
            session.auth = True
            return AuthResult(success=True)
        print(f"Authentication failed for user: {username}")
        return AuthResult(success=False)

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        """Handle RCPT command."""
        envelope.rcpt_tos.append(address)
        return '250 OK'

    async def handle_DATA(self, server, session, envelope):
        """Handle DATA command."""
        message_data = envelope.content
        email_message = BytesParser(policy=default).parsebytes(message_data)

        subject = email_message['subject']
        from_addr = email_message['from']
        to_addr = envelope.rcpt_tos[0]
        body = email_message.get_body(preferencelist=('plain')).get_content()
        html_body = email_message.get_body(preferencelist=('html')).get_content() if email_message.get_body(preferencelist=('html')) else None

        print(f"Received email from {from_addr} to {to_addr}")

        await self.send_email_with_brevo(from_addr, to_addr, subject, body, html_body)
        return '250 Message acce
