# webservertune-enhance

**Version:** 0.1.0  
**Location:** `/opt/webservertune-enhance/`  
**Author:** rdbf  

## Overview

webservertune-enhance is an automated configuration management service for Enhance hosting environments that handles both Nginx and OpenLiteSpeed webservers from a single, unified service. It detects which webserver is active, loads the appropriate modules, and watches for configuration changes, re-applying settings automatically without manual intervention. Future Enhance updates might break the functionality, although checks are in place to prevent this. The service is compatible with all Enhance v12 releases, up to and including 12.16.0.

## Objectives

1. **Unified Webserver Management**: One service, one config file, for both Nginx and OpenLiteSpeed
2. **HTTP/3 Protocol Support**: Enable HTTP/3 with QUIC listeners and Alt-Svc headers on Nginx
3. **Centralized Security**: Implement modular security configurations across all websites on one server on Nginx
4. **OLS Configuration Enforcement**: Maintain desired OpenLiteSpeed settings that Enhance periodically overwrites
5. **503 Auto-Recovery**: Introduce automatic recovery from HTTP 503 errors, which isn't possible with standard OpenLiteSpeed config on Enhance due to the separation of OLS and LSPHP
6. **Quality of Life Modifications**: Persistent logging, FastCGI cache management, and Client Max Body Size modification for Nginx

## Features

### Configuration Management
- **Reversible Changes**: All modifications can be undone by changing feature toggles or values
- **Targeted Processing**: Only modifies files when changes are actually needed
- **State Detection**: Analyzes current configuration to determine required actions
- **Automatic Backup**: Creates timestamped backups before any changes, with rollback on failure

### Webserver Detection
- Detects the active webserver on startup and loads the appropriate modules
- Monitors for webserver transitions (e.g. Enhance switching from Nginx to OLS) and restarts automatically

### Nginx Features Managed
- **Listen Directives**: HTTP/2 and HTTP/3/QUIC listeners with proper IPv6 support
- **Protocol Configuration**: http2 on, http3 on, and quic_gso directives
- **HTTP/3 Compatibility**: Alt-Svc headers and FastCGI HTTP_HOST parameter
- **Performance Optimization**: reuseport, quic_gso, and FastCGI cache management
- **Security Modules**: SSL configuration, server hardening, and CMS protection includes
- **Logging Features**: Persistent logging and Cloudflare real IP detection
- **Other Settings**: FastCGI cache management and Client Max Body Size modification

### OLS Features Managed
- **Configuration Enforcement**: Key/value settings enforced in `httpd_config.conf` after every Enhance-triggered change
- **503 Auto-Recovery**: Monitors per-site access logs for PHP 503 spikes and triggers PHP restarts via the Enhance API

### Security Features (Nginx only)
- **SSL Configuration**: Modern TLS protocols and secure cipher suites
- **Server Hardening**: Basic server hardening measures
- **CMS Protection**: WordPress-specific security rules and file access restrictions

## Installation and Usage

### Requirements
- Root access required
- Enhance hosting environment
- Python 3.11+
- inotify-tools: `apt install inotify-tools`
- Nginx with HTTP/3 support compiled in (current Enhance Nginx version 1.26.3 has this)

### Quick Install
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
2. Follow the Quick Install steps above, copying across your existing config values
3. Verify the service works correctly and behaves as before
4. Remove `/opt/nginxtune-enhance` if desired

### Verification
```bash
# Check service status
systemctl status webservertune-enhance

# Check all logs
tail -f /var/log/webservertune-enhance/*.log

# Check individual logs
tail -f /var/log/webservertune-enhance/webservertune-enhance.log
tail -f /var/log/webservertune-enhance/nginxtune.log
tail -f /var/log/webservertune-enhance/olstune.log
tail -f /var/log/webservertune-enhance/ols503fix.log
```

## Logging

All operations are logged to `/var/log/webservertune-enhance/` with timestamps. Each component writes to its own log file:

| File | Content |
|------|---------|
| `webservertune-enhance.log` | Main program: startup, webserver detection, transitions |
| `nginxtune.log` | Nginx config changes, reloads, backups |
| `olstune.log` | OLS config enforcement, backups, restarts |
| `ols503fix.log` | 503 detection events and PHP restart actions |

Log level is configurable via `settings.conf`. `INFO` is the recommended default and shows all operational activity. `DEBUG` adds low-level inotify event detail. `WARNING` shows only unexpected events and errors.

### Persistent Logging
When `persistent_logging` is enabled under `[nginx-features]`:
- Access logs are also written to `/var/www/<UUID>/logs/webserver.log`
- Uses a modified log format with additional fields
- Real visitor IPs are logged when `real_ip_logging` is enabled (extracts Cloudflare visitor IPs instead of edge server IPs)

## Backup System

- **Automatic Backups**: Creates timestamped backups of all site configs before any changes
- **Location**: `/opt/webservertune-enhance/backups/nginx/YYYYMMDD_HHMMSS/`
- **Validation**: Tests Nginx configuration with `nginx -t` before applying changes
- **Rollback**: Automatically restores from backup and reloads if validation or reload fails, then restarts the service to re-attempt changes
- **Retention**: Configurable cleanup of old backups (default 30 days)

## File Structure

```
/opt/webservertune-enhance/
├── webservertune-enhance          # Orchestrator — detects webserver, loads modules
├── settings.conf                  # Active configuration (contains API token — keep private)
├── settings.conf.example          # Configuration template
├── webservertune-enhance.service  # systemd service unit
├── modules/
│   ├── nginxtune                  # Nginx configuration manager
│   ├── olstune                    # OLS configuration enforcer
│   └── ols503fix                  # OLS 503 auto-recovery
├── overrides/
│   ├── ssl.conf                   # SSL A+ security settings
│   ├── hardening.conf             # Server hardening configuration
│   └── cms.conf                   # CMS/WordPress protection rules
└── backups/
    ├── nginx/                     # Nginx config backups
    └── ols/                       # OLS config backups
```

## Configuration

The `settings.conf` file uses TOML format and controls all features through a single file.

### General

| Setting | Default | Description |
|---------|---------|-------------|
| `log_level` | `INFO` | Log verbosity: `DEBUG` (everything), `INFO` (normal operations), `WARNING` (unexpected events and errors only) |
| `debounce_seconds` | `10` | Seconds to wait after a file change event before acting, to avoid reacting to partial writes |

### Nginx

| Setting | Default | Description |
|---------|---------|-------------|
| `backup_retention_days` | `30` | Days to retain backups in `backups/nginx/` |
| `http3_enable` | `false` | HTTP/3 support: QUIC listeners, Alt-Svc headers, FastCGI HTTP_HOST fix |
| `quic_gso_enable` | `false` | QUIC Generic Segmentation Offloading — requires `http3_enable = true` |
| `ssl_upgrade` | `false` | Include `overrides/ssl.conf` — modern TLS settings |
| `server_hardening` | `false` | Include `overrides/hardening.conf` — server hardening rules |
| `cms_protection` | `false` | Include `overrides/cms.conf` — WordPress and CMS protection rules |
| `persistent_logging` | `false` | Persistent access logs to `/var/www/<UUID>/logs/webserver.log` |
| `real_ip_logging` | `false` | Log real visitor IPs via Cloudflare headers — requires `persistent_logging = true` |
| `fastcgi_cache_inactive` | `60m` | FastCGI cache inactive timeout |
| `fastcgi_cache_valid` | `60m` | FastCGI cache validity period |
| `client_max_body_size` | `200m` | Maximum upload and request body size |

### OLS Webserver Settings

Enforced key/value pairs in `httpd_config.conf`. Supports top-level keys under `[ols-webserver.general]` and named blocks such as `[ols-webserver.tuning]`. Any block name must match exactly as it appears in `httpd_config.conf`. Several commented out values are included in `settings.conf.example` for reference.

| Setting | Default | Description |
|---------|---------|-------------|
| `backup_retention_days` | `30` | Days to retain backups in `backups/ols/` |

### OLS 503 Fix

| Setting | Default | Description |
|---------|---------|-------------|
| `enhance_url` | — | Enhance panel API URL |
| `enhance_token` | — | Enhance API bearer token |
| `window_seconds` | `30` | Sliding window in seconds for 503 counting |
| `min_503_count` | `5` | Minimum 503 count within the window before evaluating a restart |
| `min_503_percent` | `50` | Minimum percentage of recent requests that must be 503s to trigger a restart |
| `last_n_requests` | `10` | Request sample size for percentage calculation |
| `cooldown_seconds` | `60` | Minimum time between restarts for the same site |
| `scan_interval` | `1` | Log polling interval in seconds |

All Nginx and OpenLiteSpeed features are disabled by default, with FastCGI cache and Client Max Body Size values set to match Enhance's auto-generated defaults.

## Known Issues

The CMS overrides, when applied on the control panel, can cause issues with the Enhance file manager.  
The CMS overrides can also prevent installations of ClientExec from completing automated version updates.

## Version History

**0.1.0** - Initial release, merge nginx/ols/503 scripts, logs and configs.
