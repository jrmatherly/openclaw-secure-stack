# User Quick Start

Operations guide for deploying and running OpenClaw Secure Stack.

## What You Get After Install

Running `./install.sh` starts five containers:

| Container | Role | Port |
|-----------|------|------|
| **proxy** | Reverse proxy — authenticates API requests, sanitizes prompts, forwards to OpenClaw | `${PROXY_PORT:-8080}` on the host |
| **openclaw** | OpenClaw gateway — serves WebSocket + HTTP API | `3000` on the host |
| **caddy** | HTTPS reverse proxy for the Control UI (self-signed cert for localhost) | `${CADDY_PORT:-8443}` on the host |
| **egress-dns** | CoreDNS sidecar — forwards DNS queries to public resolvers | 172.28.0.10 (internal) |

All containers run read-only, as non-root, with dropped capabilities.

## Your API Token

The installer generates a random token and stores it in `.env` as `OPENCLAW_TOKEN`. To retrieve it:

```bash
grep OPENCLAW_TOKEN .env
```

Include it in every request:

```bash
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Hello"}]}'
```

## Common Operations

### Stop / Start / Restart

```bash
docker compose down          # stop all containers
docker compose up -d         # start in background
docker compose restart       # restart all
docker compose restart proxy # restart just the proxy
```

### View Logs

```bash
docker compose logs -f          # all containers, follow
docker compose logs -f proxy    # proxy only
docker compose logs openclaw    # openclaw output
```

## Configuration Changes

### Changing LLM Provider or API Key

Edit `.env` and set the appropriate key:

```bash
# For OpenAI
OPENAI_API_KEY=sk-...

# For Anthropic
ANTHROPIC_API_KEY=sk-ant-...
```

Then restart:

```bash
docker compose restart
```

### Changing the Proxy Port

Edit `.env`:

```bash
PROXY_PORT=9090
```

Then restart:

```bash
docker compose down && docker compose up -d
```

### Using a Custom DNS Server

By default, the stack forwards DNS queries to Google Public DNS (`8.8.8.8`). To use a filtering DNS provider that blocks malicious or unwanted domains, edit `docker/egress/Corefile`:

```text
. {
    forward . <your-dns-server-ip>
    log
    errors
}
```

Common filtering DNS options:

| Provider | IPs | What it blocks |
|----------|-----|----------------|
| Cloudflare Family | `1.1.1.3 1.0.0.3` | Malware + adult content |
| Cloudflare Malware-only | `1.1.1.2 1.0.0.2` | Malware |
| NextDNS | `45.90.28.0 45.90.30.0` | Customizable via dashboard |
| Pi-hole / AdGuard Home | Your server IP | Self-hosted, fully customizable |

Then rebuild the DNS container:

```bash
docker compose up -d --build egress-dns
```

## Control UI

Access the OpenClaw Control UI dashboard at:

```text
https://localhost:8443/?token=YOUR_OPENCLAW_TOKEN
```

Your browser will show a certificate warning (self-signed cert) — this is expected for localhost. Accept it to proceed.

Get your token with: `grep OPENCLAW_TOKEN .env`

## Telegram Integration

To connect OpenClaw to Telegram:

1. Create a bot with [@BotFather](https://t.me/BotFather) on Telegram
2. Add the bot token to `.env`:

   ```bash
   TELEGRAM_BOT_TOKEN=123456:ABC-DEF...
   ```

3. Restart: `docker compose restart openclaw`
4. Send `/start` to your bot in Telegram — you'll receive a pairing code to approve

OpenClaw uses long-polling (outbound only), so no public domain or inbound ports are needed.

## Reading the Audit Log

The proxy writes security events as JSON Lines to the audit log inside the container. To view:

```bash
docker compose exec proxy cat /var/log/audit/audit.jsonl
```

Each line is a JSON object with fields: `timestamp`, `event_type`, `source_ip`, `action`, `result`, `risk_level`, and `details`.

Event types include:

- `auth_success` / `auth_failure` — authentication attempts
- `prompt_injection` — detected prompt injection patterns
- `skill_scan` / `skill_quarantine` / `skill_override` — scanner events

## What Blocked Requests Look Like

| Scenario | HTTP Status | Meaning |
|----------|-------------|---------|
| Missing or invalid token | 401 | Authentication failed |
| Prompt injection detected (reject rule) | 400 | Request blocked by sanitizer |
| Suspicious network call in skill | Scanner finding | Flagged by AST-based code scanner |

## Re-running the Installer

Running `./install.sh` again is safe. It will:

- Preserve your existing `.env` (prompts before overwriting)
- Configure the OpenClaw gateway (HTTP API, trusted proxies, Control UI auth)
- Rebuild and restart containers

## Troubleshooting

1. **Health check fails**: Run `curl http://localhost:8080/health` — if it times out, check `docker compose ps` for container status.
2. **401 on every request**: Verify your token matches `OPENCLAW_TOKEN` in `.env`. The `Authorization` header must be `Bearer <token>`.
3. **LLM calls fail**: Check that the correct API key is set in `.env`. Verify DNS is working with `docker compose exec openclaw nslookup api.openai.com`.
4. **Container won't start**: Run `docker compose logs` to see error output. Common cause: port conflict on `PROXY_PORT`.
5. **Skills blocked unexpectedly**: Check scanner findings with `uv run python -m src.scanner.cli scan <skill-path>`. Review `config/scanner-rules.json` for rule definitions.
6. **Control UI "pairing required"**: Make sure you access via the tokenized URL: `https://localhost:8443/?token=YOUR_TOKEN`. The installer configures `allowInsecureAuth` to bypass device pairing in Docker.
7. **Telegram bot not responding**: Check `docker compose logs openclaw | grep telegram`. Verify `TELEGRAM_BOT_TOKEN` is set in `.env`.
