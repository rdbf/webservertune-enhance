# webservertune-enhance

**Version:** 0.6.1  
**Location:** `/opt/webservertune-enhance/`  
**Author:** rdbf

## Overview

webservertune-enhance is an automated configuration service for Enhance hosting control panel servers that handles both Nginx and OpenLiteSpeed webservers. It monitors for configuration changes and re-applies settings automatically without manual intervention, adding features and resolving limitations in how Enhance implements each webserver.

Future Enhance updates might break functionality, although checks are in place to prevent this. The service is compatible with all Enhance v12 releases, up to and including 12.21.3.

## Features

### General
- Single config file and service for both Nginx and OpenLiteSpeed
- Modifications applied server-wide for all websites
- Reversible changes via feature toggles — disable a feature to undo its changes
- Targeted processing — only modifies files when changes are actually needed
- Webserver transition detection — monitors for switches between Nginx and OLS and reloads automatically
- Automatic timestamped backups before any change, with rollback on failure
- Persistent logging: Per-site webserver access logs written to `/var/www/<UUID>/logs/webserver.log`, for both Nginx and OLS
- PHP log persistence: Per-site PHP error logs written to `/var/www/<UUID>/logs/php.log`, for both Nginx and OLS
- Cloudflare API health: Monitors all CF-managed domains cluster-wide for zones stuck in `Error` state and automatically re-applies the existing token via the Enhance API. Checks all websites across all servers in the cluster — only needs to run on one server.

### Nginx
- HTTP/3: QUIC listeners, Alt-Svc headers, and FastCGI HTTP_HOST in website vhosts
- QUIC directives: quic_bpf, quic_gso, quic_retry, and ssl_early_data managed in nginx.conf
- Security directives: Secure SSL/TLS versions, basic hardening, and basic CMS/WordPress protection
- Persistent logging: Per-site access logs with optional Cloudflare real IP detection
- FastCGI cache settings: Configurable inactive timeout and cache validity period
- FastCGI clearing: Clear Nginx FastCGI cache via the Enhance API when a WordPress update completes
- Client Max Body Size: Configurable maximum upload and request body size
- Redirects: Syncs and fixes redirect rules created in the Enhance UI to Nginx, per domain
- Systemd service: Adds config to fix default restart behaviour (5x max, then "dead forever") to keep restarting at slower pace forever

### OLS
- Persistent config: Enforces key/value settings in `httpd_config.conf`, re-applied automatically whenever Enhance overwrites the file
- 503 fixer: Monitors logs for http-503 spikes and triggers a PHP restart via the Enhance API when thresholds are met for a domain
- Redirects: Syncs and fixes redirect rules created in the Enhance UI to the relevant `.htaccess` file for each domain
- LSPHP setting: Sets LSAPI_CHILDREN per site via the Enhance API based on its NPROC cgroup limit

## Requirements

- Root access
- Enhance hosting environment
- Python 3.11+ (default on Ubuntu 24.04)
- Dependencies: `apt install inotify-tools python3-httpx python3-h2`
- Enhance installed updated Nginx (1.28.0) or OpenLiteSpeed (1.8.5)

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

If the version history notes "Config format changed", update `settings.conf` manually before restarting, otherwise the service will fail to start.

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
tail -f /var/log/webservertune-enhance/nginxredirects.log
tail -f /var/log/webservertune-enhance/fastcgiclear.log
tail -f /var/log/webservertune-enhance/olstune.log
tail -f /var/log/webservertune-enhance/ols503fix.log
tail -f /var/log/webservertune-enhance/olsredirects.log
tail -f /var/log/webservertune-enhance/olslsapi.log
tail -f /var/log/webservertune-enhance/cfapihealth.log
```

## Configuration

All settings are controlled through `settings.conf` in TOML format. All features are disabled by default, with FastCGI cache and Client Max Body Size set to match Enhance's defaults.

### API

| Setting | Default | Description |
|---------|---------|-------------|
| `enhance_url` | — | Enhance panel API URL |
| `enhance_org_id` | — | Enhance organisation UUID |
| `enhance_token` | — | Enhance API bearer token |
| `org_cache_ttl` | `3600` | Seconds between automatic org cache refreshes |

### General

| Setting | Default | Description |
|---------|---------|-------------|
| `log_level` | `INFO` | `DEBUG` (everything), `INFO` (normal operations), `WARNING` (errors only) |
| `debounce_seconds` | `10` | Seconds to wait after a file change before acting, to avoid reacting to partial writes - increase for servers with more sites |
| `persistent_logging` | `false` | Per-site webserver access log persistence to `/var/www/<UUID>/logs/webserver.log`. Applies to both Nginx and OLS. |
| `persistent_php_logs` | `false` | Per-site PHP error log persistence to `/var/www/<UUID>/logs/php.log`. Applies to both Nginx and OLS. |
| `nginx_restart_manage` | `false` | Manages the nginx systemd service restart configuration |
| `nginx_redirects` | `false` | Sync Enhance UI redirect rules to Nginx include files, per domain |
| `ols_503fix_enable` | `false` | Load and start the OLS 503 fix module |
| `ols_redirects` | `false` | Sync Enhance UI redirect rules to per-domain `.htaccess` files |
| `backup_retention_days` | `30` | Days to retain backups in `backups/nginx/` and `backups/ols/` |

### Nginx

| Setting | Default | Description |
|---------|---------|-------------|
| `http3_enable` | `false` | HTTP/3 support: QUIC listeners, Alt-Svc headers, FastCGI HTTP_HOST |
| `quic_directives_enable` | `false` | QUIC performance directives written to nginx.conf — requires `http3_enable = true` |
| `ssl_upgrade` | `false` | Include `overrides/ssl.conf` — modern TLS settings |
| `server_hardening` | `false` | Include `overrides/hardening.conf` — basic server hardening rules |
| `cms_protection` | `false` | Include `overrides/cms.conf` — WordPress and CMS protection rules |
| `real_ip_logging` | `false` | Log real visitor IPs via Cloudflare headers — requires `persistent_logging = true` in `[general]` |
| `fastcgi_cache_inactive` | `60m` | FastCGI cache inactive timeout |
| `fastcgi_cache_valid` | `60m` | FastCGI cache validity period |
| `client_max_body_size` | `200m` | Maximum upload and request body size |

### Nginx FastCGI Cache Clear

| Setting | Default | Description |
|---------|---------|-------------|
| `enabled` | `false` | Load and start the fastcgiclear module — Nginx only. Installs mu-plugin that catches update notifications and sets a flag for cache clearing |

### OLS Webserver Settings

Enforced key/value pairs in `httpd_config.conf`. Supports top-level keys under `[ols.general]` and named blocks such as `[ols.tuning]`. Block names must match exactly as they appear in `httpd_config.conf`. Several commented-out example values are included in `settings.conf.example` for reference. OLS in Enhance ignores / overrides some sections (like LSPHP) and other settings won't work at all due to the way OLS is implemented by Enhance.

| Setting | Default | Description |
|---------|---------|-------------|
| — | — | All settings are optional; only defined keys are enforced |

### OLS 503 Fix

| Setting | Default | Description |
|---------|---------|-------------|
| `window_seconds` | `30` | Sliding window in seconds for http-503 counting |
| `min_503_count` | `5` | Minimum http-503 count within the window before evaluating a restart |
| `min_503_percent` | `50` | Minimum percentage of recent requests that must be 503s to trigger a restart |
| `last_n_requests` | `10` | Request sample size for percentage calculation |
| `cooldown_seconds` | `60` | Minimum time between restarts for the same site to avoid rapid restart repeats |
| `scan_interval` | `1` | Log polling interval in seconds |

### OLS LSPHP Setting

| Setting | Default | Description |
|---------|---------|-------------|
| `enabled` | `false` | Load and start the olslsapi module — OLS only |
| `children_below_nproc` | `3` | lsapiChildren is set to nproc minus this value |
| `interval_seconds` | `21600` | How often to re-check and update all sites |

### Cloudflare API Health

| Setting | Default | Description |
|---------|---------|-------------|
| `enabled` | `false` | Load and start the cfapihealth module. Checks all websites across the cluster — only needs to be enabled on one server |
| `poll_interval_seconds` | `1800` | How often to check CF domain status |

## Backup System

- **Location**: `/opt/webservertune-enhance/backups/`
- **Validation**: Tests Nginx configuration with `nginx -t` before applying changes, checks OLS active state after applying changes
- **Rollback**: Restores from backup and reloads / restarts if validation or reload fails
- **Retention**: Configurable via `backup_retention_days` in `[general]`, applies to both Nginx and OLS

## Logging

Each component writes to its own log file in `/var/log/webservertune-enhance/`:

`INFO` is the default log level. `DEBUG` can add low-level inotify event detail.

### Persistent Logging

When `persistent_logging` is enabled, access logs are written to `/var/www/<UUID>/logs/webserver.log`. For Nginx, an extended log format is used and when `real_ip_logging` is enabled, Cloudflare visitor IPs are logged instead of edge server IPs. For OLS, entries are tailed from `/var/local/enhance/webserver_logs/<UUID>.log`.

When `persistent_php_logs` is enabled, PHP logs are written to `/var/www/<UUID>/logs/php.log` - php-error.log for both webservers and php-fpm.log for Nginx.

### Log Rotation

If log rotation is desired, create `/etc/logrotate.d/webservertune-enhance` with the following:

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
Adjust settings as required, as this config saves 15 weekly logs.

## Bugs, feature requests, fixes

- Please report any issues with functionality, or if you'd like to see an existing OLS/Nginx issue with Enhance fixed, if possible. The software has been tested and running on several Enhance clusters for a few months, but different clusters can have different designs and modifications, so it might behave unexpectedly.

## Known Issues

- The Nginx version that Enhance ships is built against an old OpenSSL version (v3.0.13 - 30 Jan 2024), meaning that quic/http3 performance will be poor at best.
- The CMS overrides can cause issues with the Enhance file manager when applied on the control panel, or block certain functionalities of your CMS.
- Slugs with queries ( ? ) cannot be handled by Nginx for redirection, they will not be applied, but only logged.

## Version History

**0.6.1** — Fix HTTP/1.1 issue of communication with API from controlpanel server. Switch to httpx + h2 libraries for HTTP/2 to API. New dependencies must be installed before updating to this version.

**0.6.0** — Cloudflare API health monitoring. Shared internal API client. Config format changed.

**0.5.2** — Set LSAPI_CHILDREN per site based on NPROC cgroup limit. Config format changed.

**0.5.1** — QUIC directives moved to nginx.conf, including quic_gso. Config format changed.

**0.5.0** — OLS redirect sync from Enhance UI.

**0.4.0** — Nginx redirect sync from Enhance UI.

**0.3.0** — FastCGI cache clearing on WordPress update.

**0.2.1** — nginx systemd service restart management.

**0.2.0** — Persistent webserver/php logging for OLS/Nginx.

**0.1.0** — Initial release, merging nginx/ols/503 scripts, logs, and configs.
