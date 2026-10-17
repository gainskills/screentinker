# Server logs and fail2ban

The server writes HTTP access records and authentication-failure events to its own stdout
(the application console, not the browser console). Systemd saves stdout and stderr to
`/var/log/screentinker/server.log` in the supplied native service configurations. The application
does not open a log file or require permission to write `/var/log` itself.

## Records

```text
2026-10-15T12:00:00.000Z [access] {"ip":"203.0.113.10","method":"POST","route":"/login","status":401,"duration_ms":74,"aborted":false}
2026-10-15T12:00:00.001Z [security] auth_failure ip=203.0.113.10 method=password
```

Access records are emitted once when an HTTP response completes or the connection closes. They
include anonymous requests, parser errors, static files and rate-limit rejections. A disconnected
request is recorded with `aborted:true` and synthetic status 499. Socket.IO/WebSocket messages and
the separate HTTP-to-HTTPS redirect listener are not access-logged by Express middleware.

`route` is the Express route's declared template (relative to its router), not the requested URL.
It is `-` when no route template is available, such as a static response or an early rejection.
Query strings, raw paths, bodies, cookies, Authorization headers, account names and user agents
are omitted. Paths can carry credentials too: inbound hooks, preview sessions and shared views
all have secrets in their URLs. This privacy choice also means unknown scanner paths are not
retained in these application access records.

Set `ACCESS_LOG=false` in the service's environment to stop access records on a busy instance.
Individual password/TOTP failure events remain enabled. Unknown accounts, wrong passwords and
attempts during password lockout produce password events; bad TOTP/recovery codes produce TOTP
events. SSO-policy refusals, successful logins, malformed requests and generic 401/429 responses
do not count as credential failures. SQLite activity auditing continues independently.

The `ip` uses the existing client-IP resolver and normalizes IPv4-mapped addresses. Invalid
addresses cannot become security events. Console diagnostics escape control characters,
including newlines, so an untrusted error cannot forge another security record in the shared file.
Multiline diagnostics and stack traces therefore contain literal `\n` escapes.

## Native systemd setup

New Debian/Pi server installations and `scripts/install-service.sh` install the log configuration
and rotation policy. The installer does not install or enable fail2ban. For an existing service,
create a drop-in with `sudo systemctl edit screentinker` (substitute your actual service name,
such as `screentinker-server` or `remotedisplay`):

```ini
[Service]
LogsDirectory=screentinker
LogsDirectoryMode=0750
UMask=0027
StandardOutput=append:/var/log/screentinker/server.log
StandardError=inherit
```

Then, from the repository root:

```bash
sudo apt-get install logrotate
sudo install -m 0644 scripts/logging/screentinker.logrotate /etc/logrotate.d/screentinker
sudo systemctl daemon-reload
sudo systemctl restart screentinker
sudo tail -F /var/log/screentinker/server.log
```

Systemd creates the restricted log directory for the service user. Use separate directories and
rotation policies if running multiple instances. These settings require systemd with `append:`
support (v240+). Application messages move from `journalctl` to the file; service lifecycle events
remain in the journal. The sample service's user, Node executable and checkout path must match
your installation.

Rotation is daily or above 50 MiB when logrotate runs, retaining 14 files with compression.
`maxsize` is checked when logrotate runs, not continuously; schedule logrotate more frequently
for high traffic. `copytruncate` keeps systemd's open descriptor valid without restarting the
server, with a small possible loss window during copying/truncation. This is an operational log,
not a guaranteed-delivery audit sink. Check rotation with:

```bash
sudo logrotate --debug /etc/logrotate.d/screentinker
```

## Fail2ban

For ready-to-adapt Nginx, Caddy and Cloudflare Tunnel configurations and the corresponding
firewall/API jails, see [proxy and tunnel examples](logging-proxies.md).

Use the dedicated `[security] auth_failure` events. Do not ban on every 401 or 429: legitimate
players and users behind a shared office address can generate those statuses. Combined `[limit]`
diagnostics do not represent one failed login each.

Install the examples, initially disabled:

```bash
sudo apt-get install fail2ban
sudo install -m 0644 scripts/logging/fail2ban-filter.conf /etc/fail2ban/filter.d/screentinker.conf
sudo install -m 0644 scripts/logging/fail2ban-jail.local /etc/fail2ban/jail.d/screentinker.local
sudo fail2ban-regex /var/log/screentinker/server.log /etc/fail2ban/filter.d/screentinker.conf
```

The sample jail counts 10 failed password/TOTP attempts from one IP within 10 minutes, then
bans for 15 minutes. Adjust for shared networks and include your administrator/VPN addresses in
`ignoreip` where appropriate. `usedns=no` and `<ADDR>` require numeric IP addresses.

Before setting `enabled=true`, select an action that covers the actual traffic path:

- Direct/native or a proxy on the same host: a host firewall action can work if it blocks the
  inbound connection before proxying. Verify IPv4 and IPv6.
- Cloudflare or a remote proxy: enforce at that proxy/Cloudflare or the HTTP layer. Blocking the
  visitor's IP on an origin firewall does not block packets whose source is the proxy.
- Docker published ports: verify the action affects Docker's forwarding path. A host INPUT-only
  ban may leave published container ports reachable.

Validate real-IP restoration first. The existing resolver trusts loopback/private proxy ranges
and Cloudflare ranges; a local reverse proxy must overwrite or correctly append forwarded
headers, and the backend must not be reachable through an untrusted path that can supply trusted
headers. Check the recorded IP with a controlled request from another machine. Never ban a proxy
address as though it were a visitor.

After editing the jail and choosing the action:

```bash
sudo fail2ban-client -t
sudo fail2ban-client reload
sudo fail2ban-client status screentinker
```

Use a controlled source to confirm both detection and actual HTTP blocking, then unban it.
The filter matching a line alone does not demonstrate effective network enforcement.

## Docker and other process managers

Docker continues to collect the application console; inspect it with `docker compose logs`.
The native systemd file settings do not redirect container logs. Configure the process manager's
file/journal collection and retention, or an external collector, and point fail2ban at that source.
The app itself has no `LOG_FILE` option. The supplied filter expects the application's plain
timestamped lines; Docker JSON wrappers require extraction or an adapted filter.

References: [Fail2ban filter development](https://github.com/fail2ban/fail2ban/blob/master/FILTERS),
[Cloudflare action](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/cloudflare.conf),
[logrotate manual](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in).
