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
# Clone the repository
cd /opt
git clone https://github.com/rdbf/webservertune-enhance.git

# Create config file
cd /opt/webservertune-enhance
cp settings.conf.example settings.conf

# Edit settings.conf with your desired values and Enhance API token
nano settings.conf

# Set correct permissions
chmod 755 webservertune-enhance modules/*
chmod 640 settings.conf

# Install inotify-tools if not already installed
apt install inotify-tools

# Enable and start the service
systemctl enable /opt/webservertune-enhance/webservertune-enhance.service
systemctl start webservertune-enhance
```

### Updates
```bash
cd /opt/webservertune-enhance
git pull origin main
systemctl restart webservertune-enhance
```

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

### General Settings
```toml
[general]
log_level = "INFO"           # DEBUG, INFO, WARNING
debounce_seconds = 10        # Wait time after inotify event before running
```

### Nginx Features
```toml
[nginx-features]
http3_enable = false
quic_gso_enable = false
ssl_upgrade = false
server_hardening = false
cms_protection = false
persistent_logging = false
real_ip_logging = false
fastcgi_cache_inactive = "60m"
fastcgi_cache_valid = "60m"
client_max_body_size = "200m"
backup_retention_days = 30
```

### OLS Webserver Settings
Enforced key/value pairs in `httpd_config.conf`. Supports top-level keys and named blocks:
```toml
[ols-webserver.general]
inMemBufSize = "128M"
showVersionNumber = "0"

[ols-webserver.tuning]
maxConnections = "10000"
sndBufSize = "512K"
rcvBufSize = "512K"

backup_retention_days = 30
```

### OLS 503 Fix
```toml
[ols-503fix]
error_threshold = 5           # Number of 503s to trigger a restart
window_seconds = 30           # Time window for counting 503s
last_n_requests = 10          # Minimum recent requests before triggering
error_percentage = 50         # Percentage of last_n_requests that must be 503s
cooldown_seconds = 300        # Minimum time between restarts for same site
enhance_api_url = "https://your-panel.example.com"
enhance_api_token = "your-token-here"
```

All Nginx features are disabled by default, with FastCGI cache and Client Max Body Size values set to match Enhance's auto-generated defaults.

## Known Issues

The CMS overrides, when applied on the control panel, can cause issues with the Enhance file manager.  
The CMS overrides can also prevent installations of ClientExec from completing automated version updates.

## Version History

**0.1.0** - Initial release, merge nginx/ols/503 scripts, logs and configs.
