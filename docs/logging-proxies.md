# Fail2ban examples: Nginx, Caddy and Cloudflare Tunnel

All examples read ScreenTinker's `[security] auth_failure` records from
`/var/log/screentinker/server.log`, using the filter in [logging.md](logging.md#fail2ban).
They do not require separate filters for Nginx, Caddy or Cloudflare. The proxy restores the
visitor IP; the jail selects where to enforce a ban.

| Public traffic path | Example proxy configuration | Ban enforcement |
| --- | --- | --- |
| Visitor → Nginx → app, all native on one host | [nginx-direct.conf](../scripts/logging/examples/nginx-direct.conf) | Host nftables, TCP/UDP 80 and 443 |
| Visitor → Caddy → app, all native on one host | [Caddyfile-direct](../scripts/logging/examples/Caddyfile-direct) | Host nftables, including UDP for HTTP/3 |
| Visitor → Cloudflare → cloudflared → Nginx → app | [cloudflared.yml](../scripts/logging/examples/cloudflared.yml) + [nginx-tunnel.conf](../scripts/logging/examples/nginx-tunnel.conf) | Cloudflare API |
| Visitor → Cloudflare → cloudflared → Caddy → app | [cloudflared.yml](../scripts/logging/examples/cloudflared.yml) + [Caddyfile-tunnel](../scripts/logging/examples/Caddyfile-tunnel) | Cloudflare API |

These are configuration examples, not an installer. Replace `signage.example.com`, certificate
paths, tunnel UUID and credentials path. Choose one jail and one proxy variant. Keep port 3001
private using the host firewall or a Docker loopback port binding; the native server currently
listens on all interfaces. The examples assume the app serves HTTP on port 3001 without its own
TLS certificates. If it serves HTTPS on 3443, adjust the upstream protocol, port and certificate
verification instead.

## Direct public Nginx or Caddy

Use the direct proxy example when visitors connect to that proxy itself, without Cloudflare or
another upstream proxy. Both examples overwrite `X-Forwarded-For` with the TCP client's address
and remove `CF-Connecting-IP`. This stops a public client choosing the address written to the
application log. WebSockets are supported; Caddy handles their upgrade automatically.

Nginx needs its own valid TLS certificate at the specified paths. Its file belongs in the
`http {}` configuration context, usually via `sites-enabled` or `conf.d`. The Caddy example
uses automatic HTTPS. Validate before reloading:

```bash
sudo nginx -t
# Or, for Caddy:
sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
```

Install the direct jail instead of the generic one, from the repository root:

```bash
sudo install -m 0644 scripts/logging/examples/fail2ban-direct.local /etc/fail2ban/jail.d/screentinker.local
```

It uses Fail2ban's `nftables` action with both TCP and UDP on 80/443, so Caddy's HTTP/3 listener
is covered. It requires nftables and Fail2ban on the public proxy host. It assumes native
listeners reached through the host INPUT path; Docker-published proxy ports need an action
covering Docker forwarding instead. If proxy and app run on different machines, collect the
application security events on the proxy host or arrange remote enforcement there.

Do not use the direct proxy examples unchanged behind Cloudflare: they would forward the
Cloudflare edge/connector IP, rather than the visitor IP.

## Cloudflare Tunnel with Nginx or Caddy

The examples deliberately put a loopback proxy between `cloudflared` and the app:

```text
Visitor → Cloudflare → cloudflared → 127.0.0.1:8080 proxy → 127.0.0.1:3001 app
```

Choose **one** tunnel proxy example. Both listen only on `127.0.0.1:8080`, trust the local
connector's `CF-Connecting-IP`, and pass a single normalized `X-Forwarded-For` to the app.
Neither forwards the original header chain. They set the upstream scheme to HTTPS because
the public hostname uses HTTPS at Cloudflare. These listeners assume local processes are
trusted; do not expose port 8080 or broaden trust to arbitrary private networks.

Nginx requires `ngx_http_realip_module`; check `nginx -V`. Caddy requires 2.8+ for
`trusted_proxies_strict`. Its global options must be merged into an existing global block
if the Caddyfile already has one. Scope these trust settings to a dedicated tunnel listener
configuration rather than applying them indiscriminately to unrelated public sites.

For a locally managed named tunnel, adapt [cloudflared.yml](../scripts/logging/examples/cloudflared.yml)
and validate it:

```bash
cloudflared tunnel --config /etc/cloudflared/config.yml ingress validate
```

For a dashboard-managed tunnel, configure the public hostname's HTTP service as
`http://127.0.0.1:8080` and its HTTP Host Header as `signage.example.com` instead. Do not run
both management styles for the same connector. The loopback addresses assume all processes
run natively on the same host; in containers, use the actual private network and narrowly
trusted connector addresses instead.

ScreenTinker's resolver deliberately does not trust `CF-Connecting-IP` just because its peer
is loopback. The proxy examples restore that header into a safe forwarding chain without
weakening this application-level check. Avoid Cloudflare Pseudo IPv4's **Overwrite Headers**
mode for these examples: it replaces the real IPv6 visitor address with a synthetic IPv4 address.

### Cloudflare ban action

The same Cloudflare jail applies to Tunnel and ordinary orange-cloud proxied DNS. An origin
firewall ban on the visitor's address cannot stop Cloudflare's connection or an outbound tunnel.
This example creates IP Access rules for the selected Cloudflare zone, affecting its proxied
hostnames, not just ScreenTinker. It requires API access to list, create and delete those rules;
a tunnel connector token alone is insufficient.

Install the Cloudflare jail and action wrapper:

```bash
sudo apt-get install curl jq
sudo install -m 0644 scripts/logging/examples/fail2ban-cloudflare-action.conf /etc/fail2ban/action.d/screentinker-cloudflare.conf
sudo install -m 0644 scripts/logging/examples/fail2ban-cloudflare.local /etc/fail2ban/jail.d/screentinker.local
sudo touch /etc/fail2ban/action.d/screentinker-cloudflare.local
sudo chown root:root /etc/fail2ban/action.d/screentinker-cloudflare.local
sudo chmod 0600 /etc/fail2ban/action.d/screentinker-cloudflare.local
sudoedit /etc/fail2ban/action.d/screentinker-cloudflare.local
```

Put the following in the root-owned local action file, using an API token authorized for the
chosen zone's IP Access rules:

```ini
[Init]
cfzone = YOUR_ZONE_ID
cftoken = YOUR_API_TOKEN
```

The wrapper includes the distribution's `cloudflare.conf`, overriding `_cf_api_url` to the
zone endpoint and `_cf_api_prms` to bearer-token authentication. Check those variable names
exist in the installed action; distributions may ship older variants. It preserves the
upstream IPv4/IPv6 target selection. The credential filename is an action override, not a jail.
Keep real tokens out of the repository and shared diagnostic output.

With ordinary proxied DNS (no tunnel), restore the visitor IP at the public proxy by trusting
only [Cloudflare's published address ranges](https://www.cloudflare.com/ips/), then forward
that normalized address to the app. Do not use the tunnel's loopback trust rules for incoming
Internet connections. This guide supplies Tunnel proxy configurations; a public CDN origin
needs its own CIDR-based proxy configuration and origin access restrictions.

## Verify the chosen setup

From another machine, send **one** failed login with deliberately false forwarding headers:

```bash
curl -i https://signage.example.com/api/auth/login \
  -H 'Content-Type: application/json' \
  -H 'X-Forwarded-For: 203.0.113.123' \
  -H 'CF-Connecting-IP: 203.0.113.123' \
  --data '{"email":"fail2ban-probe@example.invalid","password":"incorrect"}'
```

The application security event must contain the test machine's actual public egress address,
not `203.0.113.123`, loopback, the connector, or a Cloudflare edge. Then run:

```bash
sudo fail2ban-regex /var/log/screentinker/server.log /etc/fail2ban/filter.d/screentinker.conf
sudo fail2ban-client -t
```

After replacing credentials, confirming the IP and setting `enabled=true` in the chosen jail,
reload Fail2ban. From an expendable test source, reach the configured failure threshold and
check that a **new** HTTP request is blocked. For Cloudflare, also confirm the rule exists in
the correct zone; an upstream API error can leave a local Fail2ban status showing a ban without
effective enforcement. Test IPv6 separately if enabled. Keep administrator/VPN addresses out of
the test and configure `ignoreip` to suit your deployment.

```bash
sudo fail2ban-client reload
sudo fail2ban-client status screentinker
# Substitute the actual controlled test address to clean up:
sudo fail2ban-client set screentinker unbanip TEST_SOURCE_IP
```

A fresh request is the enforcement check; existing WebSocket sessions are not guaranteed to
be disconnected by a new firewall or Cloudflare rule.

## References

- [Nginx real-IP module](https://nginx.org/en/docs/http/ngx_http_realip_module.html)
- [Caddy proxy headers](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#headers)
- [Caddy trusted proxies and client-IP headers](https://caddyserver.com/docs/caddyfile/options#trusted_proxies)
- [Cloudflare visitor-IP headers](https://developers.cloudflare.com/fundamentals/reference/http-headers/)
- [Cloudflare Tunnel configuration](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [Fail2ban Cloudflare action](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/cloudflare.conf)
- [Cloudflare IP Access Rules API](https://developers.cloudflare.com/api/resources/firewall/subresources/access_rules/methods/create/)
