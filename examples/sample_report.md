# Network Reconnaissance Report

Generated: 2026-10-26 18:41:30

## Executive Summary

- Total hosts: 1
- Total open ports: 2

> An open port does not necessarily indicate a vulnerability.

## Host Details

### Host: 192.168.56.101

**Status:** up

| Port | Protocol | Service | Product | Version |
|------|----------|---------|---------|---------|
| 22 | tcp | ssh | OpenSSH | 9.6 |
| 80 | tcp | http | Apache httpd | 2.4 |

## Enumeration Recommendations

### 192.168.56.101:22/tcp

**Service:** ssh

**Recommended checks:** Review SSH configuration, authentication methods and exposed version.

### 192.168.56.101:80/tcp

**Service:** http

**Recommended checks:** Enumerate web technologies, directories, headers and authentication.
