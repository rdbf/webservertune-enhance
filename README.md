# webservertune-enhance

**Version:** 0.2.0  
**Location:** `/opt/webservertune-enhance/`  
**Author:** rdbf

## Overview

webservertune-enhance is an automated configuration service for Enhance hosting control panel servers that handles both Nginx and OpenLiteSpeed webservers. It monitors for configuration changes and re-applies settings automatically without manual intervention, adding features and resolving limitations in how Enhance implements each webserver.

Future Enhance updates might break functionality, although checks are in place to prevent this. The service is compatible with all Enhance v12 releases, up to and including 12.16.0.

## Features

### General
- Single config file and service for both Nginx and OpenLiteSpeed
- Reversible changes via feature toggles — disable a feature to undo its changes
- Targeted processing — only modifies files when changes are actually needed
- Webserver transition detection — monitors for switches between Nginx and OLS and reloads automatically
- Automatic timestamped backups before any change, with rollback on failure
- **Persistent logging**: Per-site webserver access logs written to `/var/www/<UUID>/logs/webserver.log`, for both Nginx and OLS
- **PHP log persistence**: Per-site PHP error logs written to `/var/www/<UUID>/logs/php.log`, for both Nginx and OLS

### Nginx
- **HTTP/3**: QUIC listeners, Alt-Svc headers, and FastCGI HTTP_HOST fix, with optional QUIC Generic Segmentation Offloading (GSO)
- **Security directives**: SSL, server hardening, and basic CMS/WordPress protection improvements, applied across all sites on the server
- **Persistent logging**: Per-site access logs with optional Cloudflare real IP detection
- **FastCGI cache**: Configurable inactive timeout and cache validity period
- **Client Max Body Size**: Configurable maximum upload and request body size

### OLS — Persistent Config

Enforce key/value settings in `httpd_config.conf` that Enhance periodically overwrites. Settings are re-applied automatically whenever Enhance modifies the file.

> **Note:** Not all OLS settings are honoured by Enhance regardless of what is written to `httpd_config.conf`. This includes all lsphp/lsapi settings and 503 error handling — these cannot be controlled through this config.

### OLS — 503 Fix

In Enhance, PHP runs in the website's own isolated container and is managed directly by Enhance, meaning OLS cannot control PHP restarts. When PHP becomes stuck due to resource exhaustion — bot storms, DDoS, underpowered hardware, inefficient resource limits, or poor website code — this results in sustained 503 errors with no self-recovery. This module monitors per-site access logs for 503 spikes and triggers a PHP restart via the Enhance API when thresholds are met, allowing the site to recover. It does not address the underlying cause of the 503 spikes.

## Requirements

- Root access
- Enhance hosting environment
- Python 3.11+
- inotify-tools: `apt install inotify-tools`
- Nginx with HTTP/3 support compiled in (Enhance Nginx 1.26.3 includes this)

## Installation

```bash
git clone https://github.com/rdbf/webservertune-enhance.git /opt/webservertune-enhance
cp /opt/webservertune-enhance/settings.conf.example /opt/webservertune-enhance/settings.conf
chmod 640 /opt/webservertune-enhance/settings.conf
nano /opt/webservertune-enhance/settings.conf
systemctl enable /opt/webservertune-enhance/webservertune-enhance.service
systemctl start webservertune-enhance
```

### Updates

```bash
cd /opt/webservertune-enhance
git pull
systemctl restart webservertune-enhance
```

### Migration from nginxtune-enhance

1. Remove or comment out the nginxtune-enhance cron job: `crontab -e`
2. Follow the installation steps above, copying across your existing config values
3. Verify the service works correctly
4. Remove `/opt/nginxtune-enhance` if desired

### Verification

```bash
# Check service status
systemctl status webservertune-enhance

# Follow all logs
tail -f /var/log/webservertune-enhance/*.log

# Follow individual logs
tail -f /var/log/webservertune-enhance/webservertune-enhance.log
tail -f /var/log/webservertune-enhance/nginxtune.log
tail -f /var/log/webservertune-enhance/olstune.log
tail -f /var/log/webservertune-enhance/ols503fix.log
```

## Configuration

All settings are controlled through `settings.conf` in TOML format. All features are disabled by default, with FastCGI cache and Client Max Body Size set to match Enhance's defaults.

### General

| Setting | Default | Description |
|---------|---------|-------------|
| `log_level` | `INFO` | `DEBUG` (everything), `INFO` (normal operations), `WARNING` (errors only) |
| `debounce_seconds` | `10` | Seconds to wait after a file change before acting, to avoid reacting to partial writes |
| `persistent_logging` | `false` | Per-site webserver access log persistence to `/var/www/<UUID>/logs/webserver.log`. Applies to both Nginx and OLS. |
| `persistent_php_logs` | `false` | Per-site PHP error log persistence to `/var/www/<UUID>/logs/php.log`. Applies to both Nginx and OLS. |
| `ols_503fix_enable` | `false` | Load and start the OLS 503 fix module |

### Nginx

| Setting | Default | Description |
|---------|---------|-------------|
| `backup_retention_days` | `30` | Days to retain backups in `backups/nginx/` |
| `http3_enable` | `false` | HTTP/3 support: QUIC listeners, Alt-Svc headers, FastCGI HTTP_HOST fix |
| `quic_gso_enable` | `false` | QUIC Generic Segmentation Offloading — requires `http3_enable = true` |
| `ssl_upgrade` | `false` | Include `overrides/ssl.conf` — modern TLS settings |
| `server_hardening` | `false` | Include `overrides/hardening.conf` — server hardening rules |
| `cms_protection` | `false` | Include `overrides/cms.conf` — WordPress and CMS protection rules |
| `real_ip_logging` | `false` | Log real visitor IPs via Cloudflare headers — requires `persistent_logging = true` in `[general]` |
| `fastcgi_cache_inactive` | `60m` | FastCGI cache inactive timeout |
| `fastcgi_cache_valid` | `60m` | FastCGI cache validity period |
| `client_max_body_size` | `200m` | Maximum upload and request body size |

### OLS Webserver Settings

Enforced key/value pairs in `httpd_config.conf`. Supports top-level keys under `[ols-webserver.general]` and named blocks such as `[ols-webserver.tuning]`. Block names must match exactly as they appear in `httpd_config.conf`. Several commented-out example values are included in `settings.conf.example` for reference.

| Setting | Default | Description |
|---------|---------|-------------|
| `backup_retention_days` | `30` | Days to retain backups in `backups/ols/` |

### OLS 503 Fix

| Setting | Default | Description |
|---------|---------|-------------|
| `enhance_url` | — | Enhance panel API URL |
| `enhance_org_id` | — | Enhance organisation UUID |
| `enhance_token` | — | Enhance API bearer token |
| `window_seconds` | `30` | Sliding window in seconds for 503 counting |
| `min_503_count` | `5` | Minimum 503 count within the window before evaluating a restart |
| `min_503_percent` | `50` | Minimum percentage of recent requests that must be 503s to trigger a restart |
| `last_n_requests` | `10` | Request sample size for percentage calculation |
| `cooldown_seconds` | `60` | Minimum time between restarts for the same site |
| `scan_interval` | `1` | Log polling interval in seconds |

## Backup System

- **Location**: `/opt/webservertune-enhance/backups/`
- **Validation**: Tests Nginx configuration with `nginx -t` before applying changes
- **Rollback**: Restores from backup and reloads if validation or reload fails, then restarts the service to re-attempt
- **Retention**: Configurable per webserver (default 30 days)

## Logging

Each component writes to its own log file in `/var/log/webservertune-enhance/`:

| File | Content |
|------|---------|
| `webservertune-enhance.log` | Startup, webserver detection, transitions |
| `nginxtune.log` | Nginx config changes, reloads, backups |
| `olstune.log` | OLS config enforcement, backups, restarts |
| `ols503fix.log` | 503 detection events and PHP restart actions |

`INFO` is the recommended log level. `DEBUG` adds low-level inotify event detail.

### Persistent Logging

When `persistent_logging` is enabled, access logs are written to `/var/www/<UUID>/logs/webserver.log`. For Nginx, an extended log format is used and when `real_ip_logging` is also enabled, Cloudflare visitor IPs are logged instead of edge server IPs. For OLS, entries are tailed from `/var/local/enhance/webserver_logs/<UUID>.log`.

When `persistent_php_logs` is enabled, PHP logs are written to `/var/www/<UUID>/logs/php.log` - php-error.log for both webservers and php-fpm.log for Nginx.

### Log Rotation

Create `/etc/logrotate.d/webservertune-enhance` with the following:

```
/var/log/webservertune-enhance/*.log
/var/www/*/logs/webserver.log
/var/www/*/logs/php.log
/var/log/nginx/error.log
/var/log/nginx/access.log
{
   rotate 15
   weekly
   missingok
   notifempty
   compress
   delaycompress
   copytruncate
}
```

## Known Issues

- The CMS overrides can cause issues with the Enhance file manager when applied on the control panel. They can also prevent ClientExec from completing automated version updates.

## Version History

**0.2.0** — Persistent webserver/php logging for OLS/Nginx.
**0.1.0** — Initial release, merging nginx/ols/503 scripts, logs, and configs.
