#!/usr/bin/env python3
"""Pyxis guided installer.

A console wizard that takes a bare host to a running Pyxis instance. It checks
for a usable Docker (and helps install one), asks how the service should be
reached — Traefik, another reverse proxy, or a plain published port — then
collects the domain, an optional custom port and the first administrator,
generates the secrets, writes a `.env` and a `docker-compose.yml` matched to
those answers, and finally builds, starts and health-checks the stack.

    sudo ./install.py                 # the wizard
    sudo ./install.py --dry-run       # answer everything, write nothing
    sudo ./install.py --answers a.json --non-interactive

Nothing is written or executed before the review screen: every earlier step
only collects answers.
"""

from __future__ import annotations

import argparse
import curses
import grp
import ipaddress
import json
import os
import platform
import pwd
import re
import secrets
import shutil
import socket
import subprocess
import sys
import textwrap
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict, fields as dc_fields
from datetime import datetime, timezone
from pathlib import Path

# --- constants -------------------------------------------------------------

APP = "Pyxis"
DRY_RUN = False                   # set from --dry-run; relaxes the Docker gate
PROJECT = "pyxis"                 # docker compose project name
CONTAINER_UID = 10001             # the image's unprivileged user
CONTAINER_PORT = 8080
MIN_PASSWORD_LEN = 12             # mirrors minPasswordLen in handlers_users.go
DEFAULT_INSTALL_DIR = "/srv/docker/pyxis"
DEFAULT_TRAEFIK_DIR = "/srv/docker/traefik"
GIB = 1024 ** 3
MIB = 1024 ** 2


class InstallError(Exception):
    """A step failed in a way the operator has to see."""


class Aborted(Exception):
    """The operator quit the wizard."""


# --- answers ---------------------------------------------------------------


@dataclass
class Config:
    """Every answer the wizard collects. Serialisable to JSON for a re-run."""

    repo_dir: str = ""
    install_dir: str = DEFAULT_INSTALL_DIR

    # exposure: how a browser reaches the app
    expose: str = "traefik"          # traefik | proxy | direct
    domain: str = ""
    https: bool = True               # only asked for proxy/direct
    custom_port: bool = False
    port: int = 8080
    bind_all: bool = False           # publish on 0.0.0.0 rather than 127.0.0.1

    # traefik
    traefik_install: bool = False
    traefik_dir: str = DEFAULT_TRAEFIK_DIR
    traefik_network: str = "proxy"
    traefik_entrypoint: str = "websecure"
    traefik_certresolver: str = "le"
    traefik_redirect: bool = True
    acme_email: str = ""

    # other reverse proxy
    proxy_kind: str = "nginx"        # nginx | caddy | apache

    # credentials
    admin_user: str = "admin"
    admin_pass: str = ""
    postgres_password: str = ""
    file_key: str = ""

    # tuning
    trusted_cidrs: str = ""
    max_upload_mb: int = 512
    quota_user_gb: int = 20
    quota_user_files: int = 1000
    quota_total_gb: int = 0
    disk_min_free_gb: int = 1

    # single sign-on (optional; also configurable later in /admin/settings)
    oidc_enabled: bool = False
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_allowed_domain: str = ""

    # finishing touches
    backup_cron: bool = False
    write_proxy_snippet: bool = True
    start_now: bool = True

    def base_url(self) -> str:
        scheme = "https" if (self.expose == "traefik" or self.https) else "http"
        host = self.domain or "localhost"
        url = f"{scheme}://{host}"
        # A non-default port is part of the address the browser must be given.
        if self.expose == "direct" and self.port not in (80, 443):
            url += f":{self.port}"
        return url

    def oidc_redirect(self) -> str:
        return self.base_url() + "/auth/oidc/callback"

    def cookie_secure(self) -> bool:
        return self.expose == "traefik" or self.https

    def publishes_port(self) -> bool:
        return self.expose in ("proxy", "direct")

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True) + "\n"

    @classmethod
    def from_dict(cls, d: dict) -> "Config":
        known = {f.name for f in dc_fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in known})


# --- host probing ----------------------------------------------------------


@dataclass
class Probe:
    """What the installer found on this machine. Re-run any time with F5."""

    root: bool = False
    sudo: bool = False
    distro: str = "unknown"
    distro_family: str = "unknown"     # debian | rhel | arch | suse | alpine | ...
    docker: str = ""                   # version string, "" when absent
    compose: str = ""                  # `docker compose version`
    daemon_ok: bool = False
    daemon_err: str = ""
    in_docker_group: bool = False
    disk_free: int = 0
    networks: list = field(default_factory=list)

    @property
    def docker_ready(self) -> bool:
        return bool(self.docker) and bool(self.compose) and self.daemon_ok

    @property
    def privileged(self) -> bool:
        return self.root or self.sudo


def run(cmd, timeout=25, cwd=None) -> tuple[int, str]:
    """Run a command, returning (exit code, combined output). Never raises."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, cwd=cwd)
    except FileNotFoundError:
        return 127, f"{cmd[0]}: not found"
    except subprocess.TimeoutExpired:
        return 124, f"{cmd[0]}: timed out after {timeout}s"
    except OSError as exc:
        return 1, str(exc)
    return p.returncode, (p.stdout + p.stderr).strip()


def read_os_release() -> dict:
    data = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                data[k] = v.strip().strip('"')
    except OSError:
        pass
    return data


def probe_host(install_dir: str) -> Probe:
    p = Probe()
    p.root = os.geteuid() == 0
    if not p.root and shutil.which("sudo"):
        # -n: never prompt. A cached or NOPASSWD credential counts as usable;
        # anything that would block on a password does not, because the wizard
        # cannot answer a prompt from inside curses.
        p.sudo = run(["sudo", "-n", "true"], timeout=5)[0] == 0

    osr = read_os_release()
    p.distro = osr.get("PRETTY_NAME") or platform.platform()
    ids = [osr.get("ID", "")] + osr.get("ID_LIKE", "").split()
    for family in ("debian", "ubuntu", "rhel", "fedora", "arch", "suse", "alpine"):
        if family in ids:
            p.distro_family = {"ubuntu": "debian", "fedora": "rhel"}.get(family, family)
            break

    rc, out = run(["docker", "--version"], timeout=10)
    if rc != 0:
        p.daemon_err = "docker is not installed"
    else:
        p.docker = out.splitlines()[0] if out else "docker"
        rc, out = run(["docker", "compose", "version"], timeout=10)
        p.compose = out.splitlines()[0] if rc == 0 and out else ""
        rc, out = run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=20)
        p.daemon_ok = rc == 0
        p.daemon_err = "" if rc == 0 else out.splitlines()[-1] if out else "docker info failed"
        if p.daemon_ok:
            rc, out = run(["docker", "network", "ls", "--format", "{{.Name}}"], timeout=10)
            if rc == 0:
                p.networks = out.split()

    try:
        user = pwd.getpwuid(os.getuid()).pw_name
        p.in_docker_group = user in grp.getgrnam("docker").gr_mem
    except (KeyError, OSError):
        p.in_docker_group = False

    probe_path = install_dir
    while probe_path and not os.path.isdir(probe_path):
        parent = os.path.dirname(probe_path)
        if parent == probe_path:
            break
        probe_path = parent
    try:
        st = os.statvfs(probe_path or "/")
        p.disk_free = st.f_bavail * st.f_frsize
    except OSError:
        p.disk_free = 0
    return p


def network_subnets(name: str) -> list[str]:
    """The CIDRs a docker network hands out, for TRUSTED_PROXY_CIDRS."""
    rc, out = run(["docker", "network", "inspect", name, "--format",
                   "{{range .IPAM.Config}}{{.Subnet}} {{end}}"], timeout=10)
    return out.split() if rc == 0 else []


def port_free(port: int, host: str = "0.0.0.0") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
        except OSError:
            return False
    return True


def primary_ip() -> str:
    """This host's outward-facing address, without sending anything."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("192.0.2.1", 9))     # TEST-NET-1: routed nowhere
            return s.getsockname()[0]
        except OSError:
            return "127.0.0.1"


def current_user() -> str:
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        return f"uid {os.getuid()}"


def human_bytes(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or unit == "TiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return str(n)


# --- validation ------------------------------------------------------------

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def valid_host(value: str) -> bool:
    value = value.strip()
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(HOSTNAME_RE.match(value))


def check_cidrs(value: str) -> str | None:
    for part in re.split(r"[,\s]+", value.strip()):
        if not part:
            continue
        try:
            ipaddress.ip_network(part, strict=False)
        except ValueError:
            return f"{part!r} is not a CIDR (try 172.16.0.0/12)"
    return None


def password_problem(pw: str) -> str | None:
    if len(pw) < MIN_PASSWORD_LEN:
        return f"at least {MIN_PASSWORD_LEN} characters (the app enforces this too)"
    return None


def gen_password(n: int = 24) -> str:
    # No shell metacharacters and no '$': these land in a .env that Compose
    # interpolates and that an operator will inevitably paste into a shell.
    alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789-_."
    return "".join(secrets.choice(alphabet) for _ in range(n))


# --- generated files -------------------------------------------------------


def env_file(cfg: Config) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# {APP} environment — written by install.py on {stamp}.",
        "# Secrets live here. Keep the mode at 0600 and back the file up:",
        "# losing FILE_ENCRYPTION_KEY loses the stored OIDC client secret.",
        "",
        "# --- database ---",
        f"POSTGRES_PASSWORD={cfg.postgres_password}",
        "",
        "# --- first administrator (only ever creates, never resets) ---",
        f"ADMIN_USERNAME={cfg.admin_user}",
        f"ADMIN_PASSWORD={cfg.admin_pass}",
        "",
        "# --- secrets at rest ---",
        "# 32-byte hex KEK for short secrets in the settings table. It does NOT",
        "# protect uploads: those are encrypted in the browser under a key this",
        "# server never sees.",
        f"FILE_ENCRYPTION_KEY={cfg.file_key}",
        "",
        "# --- proxy trust ---",
        "# Only these sources' X-Forwarded-For is believed. Too wide lets a",
        "# forged header dodge the rate limiter; empty behind a proxy makes",
        "# every visitor share one bucket.",
        f"TRUSTED_PROXY_CIDRS={cfg.trusted_cidrs}",
        "",
        "# --- limits ---",
        f"MAX_UPLOAD_BYTES={cfg.max_upload_mb * MIB}",
        f"QUOTA_USER_BYTES={cfg.quota_user_gb * GIB}",
        f"QUOTA_USER_FILES={cfg.quota_user_files}",
        f"QUOTA_TOTAL_BYTES={cfg.quota_total_gb * GIB}",
        f"DISK_MIN_FREE_BYTES={cfg.disk_min_free_gb * GIB}",
        "",
    ]
    if cfg.publishes_port():
        lines += ["# --- published port ---", f"APP_PORT={cfg.port}", ""]
    lines += ["# --- single sign-on (also editable in /admin/settings) ---"]
    if cfg.oidc_enabled:
        lines += [
            f"OIDC_ISSUER={cfg.oidc_issuer}",
            f"OIDC_CLIENT_ID={cfg.oidc_client_id}",
            f"OIDC_CLIENT_SECRET={cfg.oidc_client_secret}",
            f"OIDC_REDIRECT_URL={cfg.oidc_redirect()}",
            f"OIDC_ALLOWED_DOMAIN={cfg.oidc_allowed_domain}",
        ]
    else:
        lines += [
            "#OIDC_ISSUER=",
            "#OIDC_CLIENT_ID=",
            "#OIDC_CLIENT_SECRET=",
            f"#OIDC_REDIRECT_URL={cfg.oidc_redirect()}",
            "#OIDC_ALLOWED_DOMAIN=",
        ]
    return "\n".join(lines) + "\n"


def compose_file(cfg: Config) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    data = Path(cfg.install_dir) / "data"
    out = [
        f"# {APP} stack — written by install.py on {stamp} for the "
        f"{ {'traefik': 'Traefik', 'proxy': 'reverse-proxy', 'direct': 'direct-port'}[cfg.expose] } layout.",
        "# Re-running the installer rewrites this file; a timestamped backup is",
        "# kept next to it. Values come from .env in this directory.",
        "",
        "services:",
        "",
        "  app:",
        "    build:",
        f"      context: {cfg.repo_dir}",
        "      dockerfile: Dockerfile",
        f"    container_name: {PROJECT}-app",
        "    restart: unless-stopped",
        "    depends_on:",
        "      db:",
        "        condition: service_healthy",
        "    environment:",
        "      DATABASE_URL: postgres://pyxis:${POSTGRES_PASSWORD}@db:5432/pyxis?sslmode=disable",
        "      FILES_DIR: /data/files",
        f'      LISTEN_ADDR: ":{CONTAINER_PORT}"',
        f'      COOKIE_SECURE: "{str(cfg.cookie_secure()).lower()}"',
        "      MAX_UPLOAD_BYTES: ${MAX_UPLOAD_BYTES:-536870912}",
        "      ADMIN_USERNAME: ${ADMIN_USERNAME:-admin}",
        "      ADMIN_PASSWORD: ${ADMIN_PASSWORD:-}",
        "      OIDC_ISSUER: ${OIDC_ISSUER:-}",
        "      OIDC_CLIENT_ID: ${OIDC_CLIENT_ID:-}",
        "      OIDC_CLIENT_SECRET: ${OIDC_CLIENT_SECRET:-}",
        "      OIDC_REDIRECT_URL: ${OIDC_REDIRECT_URL:-}",
        "      OIDC_ALLOWED_DOMAIN: ${OIDC_ALLOWED_DOMAIN:-}",
        "      # Quoted: the `:?` message contains \": \", which YAML would read",
        "      # as a nested mapping and reject the whole file.",
        '      FILE_ENCRYPTION_KEY: "${FILE_ENCRYPTION_KEY:?set FILE_ENCRYPTION_KEY in .env - generate one with `openssl rand -hex 32`}"',
    ]
    if cfg.expose == "direct":
        out += ["      TRUSTED_PROXY_CIDRS: ${TRUSTED_PROXY_CIDRS:-}"]
    else:
        out += [
            "      # Required, not optional, behind a proxy: every request then",
            "      # arrives from the proxy, and an unset value makes one person",
            "      # guessing a share password rate-limit everybody.",
            '      TRUSTED_PROXY_CIDRS: "${TRUSTED_PROXY_CIDRS:?set TRUSTED_PROXY_CIDRS in .env to the network the proxy connects from}"',
        ]
    out += [
        "      QUOTA_USER_BYTES: ${QUOTA_USER_BYTES:-21474836480}",
        "      QUOTA_USER_FILES: ${QUOTA_USER_FILES:-1000}",
        "      QUOTA_TOTAL_BYTES: ${QUOTA_TOTAL_BYTES:-0}",
        "      DISK_MIN_FREE_BYTES: ${DISK_MIN_FREE_BYTES:-1073741824}",
        "    volumes:",
        f"      - {data}/files:/data/files",
        "    # /healthz fails while the database schema is not the version this",
        "    # binary expects, so a half-applied migration surfaces as unhealthy",
        "    # rather than as a service answering from a schema it cannot use.",
        "    healthcheck:",
        f'      test: ["CMD-SHELL", "wget -qO- http://127.0.0.1:{CONTAINER_PORT}/healthz || exit 1"]',
        "      interval: 30s",
        "      timeout: 5s",
        "      retries: 3",
        "      start_period: 20s",
        "    security_opt:",
        "      - no-new-privileges:true",
        "    cap_drop:",
        "      - ALL",
    ]

    if cfg.publishes_port():
        bind = "" if cfg.bind_all else "127.0.0.1:"
        out += [
            "    ports:",
            f'      - "{bind}${{APP_PORT:-{cfg.port}}}:{CONTAINER_PORT}"',
        ]
    if cfg.expose == "traefik":
        r = PROJECT
        out += [
            "    networks:",
            "      - backend",
            "      - proxy",
            "    labels:",
            "      - traefik.enable=true",
            f"      - traefik.docker.network={cfg.traefik_network}",
            f"      - traefik.http.routers.{r}.rule=Host(`{cfg.domain}`)",
            f"      - traefik.http.routers.{r}.entrypoints={cfg.traefik_entrypoint}",
            f"      - traefik.http.routers.{r}.tls=true",
            f"      - traefik.http.routers.{r}.tls.certresolver={cfg.traefik_certresolver}",
            f"      - traefik.http.services.{r}.loadbalancer.server.port={CONTAINER_PORT}",
        ]
        if cfg.traefik_redirect:
            out += [
                f"      - traefik.http.routers.{r}-http.rule=Host(`{cfg.domain}`)",
                f"      - traefik.http.routers.{r}-http.entrypoints=web",
                f"      - traefik.http.routers.{r}-http.middlewares={r}-https-redirect",
                f"      - traefik.http.middlewares.{r}-https-redirect.redirectscheme.scheme=https",
                f"      - traefik.http.middlewares.{r}-https-redirect.redirectscheme.permanent=true",
            ]
    else:
        out += ["    networks:", "      - backend"]

    out += [
        "",
        "  db:",
        "    image: postgres:16.15-alpine",
        f"    container_name: {PROJECT}-db",
        "    restart: unless-stopped",
        "    environment:",
        "      POSTGRES_DB: pyxis",
        "      POSTGRES_USER: pyxis",
        "      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}",
        "    volumes:",
        f"      - {data}/postgres:/var/lib/postgresql/data",
        "    networks:",
        "      - backend",
        "    healthcheck:",
        '      test: ["CMD-SHELL", "pg_isready -U pyxis -d pyxis"]',
        "      interval: 5s",
        "      timeout: 5s",
        "      retries: 10",
        "",
        "networks:",
        "  backend:",
    ]
    if cfg.expose == "traefik":
        out += [
            "  proxy:",
            f"    name: {cfg.traefik_network}",
            "    external: true",
        ]
    return "\n".join(out) + "\n"


def proxy_snippet(cfg: Config) -> tuple[str, str]:
    """(filename, contents) for the chosen reverse proxy."""
    host = cfg.domain
    upstream = f"127.0.0.1:{cfg.port}"
    # Ciphertext is a little larger than the plaintext ceiling: 16-byte GCM tag
    # per 64 KiB chunk plus the embedded manifest. Round the proxy limit up so
    # the app, not the proxy, is what rejects an oversized upload.
    body_mb = max(1, int(cfg.max_upload_mb * 1.05) + 8)

    if cfg.proxy_kind == "caddy":
        return "Caddyfile.pyxis", textwrap.dedent(f"""\
            # {APP} — include from your Caddyfile, or use as a site file.
            # Caddy obtains the certificate and sets X-Forwarded-For/Proto itself.
            {host} {{
                encode zstd gzip

                request_body {{
                    max_size {body_mb}MB
                }}

                reverse_proxy {upstream} {{
                    # Uploads and downloads stream; buffering them would hold a
                    # whole file in the proxy and stall the progress bar.
                    flush_interval -1
                }}
            }}
            """)

    if cfg.proxy_kind == "apache":
        return "pyxis.apache.conf", textwrap.dedent(f"""\
            # {APP} — needs mod_proxy, mod_proxy_http, mod_headers, mod_remoteip.
            # TLS lines assume certbot; adjust the paths to your certificate.
            <VirtualHost *:443>
                ServerName {host}

                SSLEngine on
                SSLCertificateFile    /etc/letsencrypt/live/{host}/fullchain.pem
                SSLCertificateKeyFile /etc/letsencrypt/live/{host}/privkey.pem

                # Per-file ceiling, a little above MAX_UPLOAD_BYTES so the app
                # is what rejects an oversized upload.
                LimitRequestBody {body_mb * MIB}

                ProxyPreserveHost On
                ProxyTimeout 300
                RequestHeader set X-Forwarded-Proto "https"
                ProxyPass        / http://{upstream}/
                ProxyPassReverse / http://{upstream}/
            </VirtualHost>

            <VirtualHost *:80>
                ServerName {host}
                Redirect permanent / https://{host}/
            </VirtualHost>
            """)

    return "pyxis.nginx.conf", textwrap.dedent(f"""\
        # {APP} — drop into /etc/nginx/sites-available (or conf.d) and reload.
        # TLS paths assume certbot; adjust them to your certificate.
        server {{
            listen 80;
            listen [::]:80;
            server_name {host};
            return 301 https://$host$request_uri;
        }}

        server {{
            listen 443 ssl;
            listen [::]:443 ssl;
            http2 on;
            server_name {host};

            ssl_certificate     /etc/letsencrypt/live/{host}/fullchain.pem;
            ssl_certificate_key /etc/letsencrypt/live/{host}/privkey.pem;

            # A little above MAX_UPLOAD_BYTES ({cfg.max_upload_mb} MiB plaintext):
            # the ciphertext carries a GCM tag per 64 KiB chunk and a manifest,
            # and the app should be what rejects an oversized upload.
            client_max_body_size {body_mb}m;

            location / {{
                proxy_pass http://{upstream};
                proxy_http_version 1.1;

                proxy_set_header Host              $host;
                proxy_set_header X-Real-IP         $remote_addr;
                proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
                proxy_set_header X-Forwarded-Proto $scheme;

                # Stream both directions: buffering an upload puts the whole
                # file in the proxy first and freezes the progress bar.
                proxy_request_buffering off;
                proxy_buffering off;

                proxy_read_timeout 300s;
                proxy_send_timeout 300s;
            }}
        }}
        """)


def traefik_stack(cfg: Config) -> str:
    return textwrap.dedent(f"""\
        # Minimal Traefik written by the {APP} installer. It terminates TLS with
        # Let's Encrypt and routes to any container carrying traefik labels on
        # the `{cfg.traefik_network}` network.
        services:
          traefik:
            image: traefik:v3.3
            container_name: traefik
            restart: unless-stopped
            command:
              - --providers.docker=true
              - --providers.docker.exposedbydefault=false
              - --providers.docker.network={cfg.traefik_network}
              - --entrypoints.web.address=:80
              - --entrypoints.websecure.address=:443
              - --certificatesresolvers.{cfg.traefik_certresolver}.acme.email={cfg.acme_email}
              - --certificatesresolvers.{cfg.traefik_certresolver}.acme.storage=/acme/acme.json
              - --certificatesresolvers.{cfg.traefik_certresolver}.acme.tlschallenge=true
              - --log.level=INFO
            ports:
              - "80:80"
              - "443:443"
            volumes:
              # Read-only: the docker provider only needs to watch containers.
              - /var/run/docker.sock:/var/run/docker.sock:ro
              - {cfg.traefik_dir}/acme:/acme
            networks:
              - proxy
            security_opt:
              - no-new-privileges:true

        networks:
          proxy:
            name: {cfg.traefik_network}
            external: true
        """)


def backup_script(cfg: Config) -> str:
    return textwrap.dedent(f"""\
        #!/bin/sh
        # Nightly {APP} database dump. Uploaded files are NOT in here: they are
        # end-to-end encrypted blobs under {cfg.install_dir}/data/files, which
        # you should back up with your normal file backup.
        #
        # Schema migrations have no down-path, so a restore is the rollback.
        set -eu

        DIR="{cfg.install_dir}/backups"
        KEEP_DAYS=14

        mkdir -p "$DIR"
        docker exec {PROJECT}-db pg_dump -U pyxis pyxis \\
            | gzip > "$DIR/pyxis-$(date +%Y%m%d-%H%M).sql.gz"
        find "$DIR" -name 'pyxis-*.sql.gz' -mtime "+$KEEP_DAYS" -delete
        """)


def install_notes(cfg: Config, probe: Probe) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    exposure = {
        "traefik": f"Traefik on the `{cfg.traefik_network}` network, router `{PROJECT}`",
        "proxy": f"a {cfg.proxy_kind} reverse proxy on this host, "
                 f"upstream {'0.0.0.0' if cfg.bind_all else '127.0.0.1'}:{cfg.port}",
        "direct": f"published directly on port {cfg.port}",
    }[cfg.expose]
    lines = [
        f"# {APP} — installation notes",
        "",
        f"Written by `install.py` on {stamp} on {probe.distro}.",
        "",
        "| | |",
        "|---|---|",
        f"| URL | {cfg.base_url()} |",
        f"| Exposure | {exposure} |",
        f"| Install directory | `{cfg.install_dir}` |",
        f"| Source (build context) | `{cfg.repo_dir}` |",
        f"| Compose project | `{PROJECT}` |",
        f"| First administrator | `{cfg.admin_user}` |",
        f"| Per-file upload limit | {cfg.max_upload_mb} MiB |",
        "",
        "## Everyday commands",
        "",
        "```sh",
        f"cd {cfg.install_dir}",
        f"docker compose -p {PROJECT} ps",
        f"docker compose -p {PROJECT} logs -f app",
        f"docker compose -p {PROJECT} up -d --build      # after pulling new source",
        f"docker compose -p {PROJECT} down               # stop (data survives)",
        "```",
        "",
        "## Where things live",
        "",
        "```",
        f"{cfg.install_dir}/.env                  secrets, mode 0600",
        f"{cfg.install_dir}/docker-compose.yml    generated stack",
        f"{cfg.install_dir}/data/files            encrypted blobs (uid {CONTAINER_UID})",
        f"{cfg.install_dir}/data/postgres         database",
        "```",
        "",
        "## Things that will bite",
        "",
        "- **Back up `.env`.** Losing `FILE_ENCRYPTION_KEY` loses the stored OIDC",
        "  client secret. It does *not* lose uploads — those are encrypted in the",
        "  browser under keys the server never had.",
        "- The first administrator is created **only when no super-admin exists**.",
        "  Changing `ADMIN_PASSWORD` later does not reset the account; change the",
        "  password in the UI instead.",
        "- `data/files` must stay owned by uid " + str(CONTAINER_UID) +
        " — the container drops every capability.",
        "- A database restore predating Argon2id leaves those accounts unable to",
        "  log in; an admin has to reset their passwords.",
        f"- `{cfg.base_url()}/healthz` prints `ok schema=v<N>`; it 503s while the",
        "  schema is not the version the binary expects.",
    ]
    if cfg.expose == "proxy":
        fname = proxy_snippet(cfg)[0]
        lines += [
            "",
            "## Reverse proxy",
            "",
            f"A ready {cfg.proxy_kind} configuration is at "
            f"`{cfg.install_dir}/reverse-proxy/{fname}`. It is **not** installed",
            "into the proxy for you: copy it in, check the certificate paths and",
            "reload. Keep `TRUSTED_PROXY_CIDRS` matching the network the proxy",
            "reaches the container from, or the rate limiter keys everyone to one",
            "bucket.",
        ]
    if cfg.oidc_enabled:
        lines += [
            "",
            "## Single sign-on",
            "",
            f"Redirect URI, byte for byte: `{cfg.oidc_redirect()}`",
            "",
            "Password login stays available — enabling SSO is additive.",
        ]
    return "\n".join(lines) + "\n"


# --- curses toolkit --------------------------------------------------------
#
# Just enough widget kit for a wizard: a vertically scrolling list of items,
# one of which has focus. Items render themselves into (lines, cursor) and get
# first refusal on every keystroke; the screen loop handles what they decline.

C_NORM, C_BAR, C_ACCENT, C_DIM, C_ERR, C_OK, C_WARN, C_FOCUS = range(1, 9)


def attr(pair: int, bold: bool = False) -> int:
    a = curses.color_pair(pair) if curses.has_colors() else 0
    if not curses.has_colors():
        # Without colour, focus and headings still have to be distinguishable.
        if pair in (C_BAR, C_FOCUS):
            a |= curses.A_REVERSE
        elif pair in (C_ACCENT, C_ERR):
            a |= curses.A_BOLD
        elif pair == C_DIM:
            a |= curses.A_DIM
    if bold:
        a |= curses.A_BOLD
    return a


def init_colors() -> None:
    if not curses.has_colors():
        return
    curses.start_color()
    try:
        curses.use_default_colors()
        bg = -1
    except curses.error:
        bg = curses.COLOR_BLACK
    curses.init_pair(C_NORM, curses.COLOR_WHITE, bg)
    curses.init_pair(C_BAR, curses.COLOR_WHITE, curses.COLOR_BLUE)
    curses.init_pair(C_ACCENT, curses.COLOR_CYAN, bg)
    curses.init_pair(C_DIM, curses.COLOR_BLUE if curses.COLORS < 16 else 8, bg)
    curses.init_pair(C_ERR, curses.COLOR_RED, bg)
    curses.init_pair(C_OK, curses.COLOR_GREEN, bg)
    curses.init_pair(C_WARN, curses.COLOR_YELLOW, bg)
    curses.init_pair(C_FOCUS, curses.COLOR_BLACK, curses.COLOR_CYAN)


def wrap(text: str, width: int, indent: str = "") -> list[str]:
    out = []
    for para in text.split("\n"):
        if not para.strip():
            out.append("")
            continue
        out += textwrap.wrap(para, max(20, width), initial_indent=indent,
                             subsequent_indent=indent,
                             break_on_hyphens=False) or [""]
    return out


class Item:
    focusable = False
    key = None

    def render(self, width: int, focused: bool):
        """Return (list of (text, attr), cursor as (line, col) or None)."""
        raise NotImplementedError

    def handle(self, ch: int, ui: "Ui"):
        return None

    def validate(self):
        return None

    def value(self):
        return None


class Static(Item):
    def __init__(self, text: str = "", pair: int = C_NORM, bold: bool = False,
                 indent: str = "", pre: bool = False):
        self.text, self.pair, self.bold, self.indent = text, pair, bold, indent
        self.pre = pre        # keep the line breaks: shell commands, not prose

    def render(self, width, focused):
        a = attr(self.pair, self.bold)
        if self.pre:
            return [(self.indent + ln, a) for ln in self.text.split("\n")], None
        return [(ln, a) for ln in wrap(self.text, width - 2, self.indent)], None


class Gap(Item):
    def render(self, width, focused):
        return [("", attr(C_NORM))], None


class Text(Item):
    focusable = True
    mask = False

    def __init__(self, key, label, value="", help="", validator=None,
                 placeholder="", width=44):
        self.key, self.label, self.help = key, label, help
        self.val = str(value)
        self.validator = validator
        self.placeholder = placeholder
        self.box = width
        self.cur = len(self.val)
        self.reveal = False

    def value(self):
        return self.val

    def shown(self):
        if self.mask and not self.reveal:
            return "*" * len(self.val)
        return self.val

    def render(self, width, focused):
        box = min(self.box, max(12, width - 6))
        text = self.shown()
        # Horizontal scroll so the cursor stays inside the box.
        start = max(0, self.cur - box + 1)
        view = text[start:start + box]
        if not text and not focused and self.placeholder:
            view, ph = self.placeholder[:box], True
        else:
            ph = False
        pad = view.ljust(box)
        lines = [(f"  {self.label}", attr(C_ACCENT if focused else C_NORM, focused))]
        field_attr = attr(C_FOCUS) if focused else attr(C_DIM if ph else C_NORM,
                                                        False) | curses.A_UNDERLINE
        lines.append((f"  [{pad}]", field_attr))
        cursor = (len(lines) - 1, 3 + (self.cur - start))
        if self.help:
            lines += [(ln, attr(C_DIM)) for ln in wrap(self.help, width - 6, "    ")]
        return lines, (cursor if focused else None)

    def handle(self, ch, ui):
        if ch in (curses.KEY_ENTER, 10, 13):
            return "next"
        if ch in (curses.KEY_BACKSPACE, 127, 8):
            if self.cur:
                self.val = self.val[:self.cur - 1] + self.val[self.cur:]
                self.cur -= 1
            return "handled"
        if ch == curses.KEY_DC:
            self.val = self.val[:self.cur] + self.val[self.cur + 1:]
            return "handled"
        if ch == curses.KEY_LEFT:
            self.cur = max(0, self.cur - 1)
            return "handled"
        if ch == curses.KEY_RIGHT:
            self.cur = min(len(self.val), self.cur + 1)
            return "handled"
        if ch == curses.KEY_HOME or ch == 1:      # Ctrl-A
            self.cur = 0
            return "handled"
        if ch == curses.KEY_END or ch == 5:       # Ctrl-E
            self.cur = len(self.val)
            return "handled"
        if ch == 21:                              # Ctrl-U clears
            self.val, self.cur = "", 0
            return "handled"
        if ch == curses.KEY_F4 and self.mask:
            self.reveal = not self.reveal
            return "handled"
        if 32 <= ch < 127:
            self.val = self.val[:self.cur] + chr(ch) + self.val[self.cur:]
            self.cur += 1
            return "handled"
        return None

    def validate(self):
        return self.validator(self.val) if self.validator else None


class Password(Text):
    mask = True

    def __init__(self, *a, generate=False, **kw):
        super().__init__(*a, **kw)
        self.generate = generate
        if self.generate and not self.help:
            self.help = "F4 shows it · F6 generates a strong one"

    def handle(self, ch, ui):
        if ch == curses.KEY_F6 and self.generate:
            self.val = gen_password()
            self.cur = len(self.val)
            self.reveal = True
            return "handled"
        return super().handle(ch, ui)


class Number(Text):
    def __init__(self, key, label, value=0, help="", lo=0, hi=1 << 40, unit=""):
        self.lo, self.hi, self.unit = lo, hi, unit
        super().__init__(key, label, str(value), help, self._check, width=14)

    def _check(self, v):
        v = v.strip()
        if not v.isdigit():
            return f"{self.label.lower()}: digits only"
        n = int(v)
        if not (self.lo <= n <= self.hi):
            return f"{self.label.lower()}: between {self.lo} and {self.hi}"
        return None

    def value(self):
        return int(self.val) if self.val.strip().isdigit() else self.lo

    def render(self, width, focused):
        lines, cur = super().render(width, focused)
        if self.unit:
            text, a = lines[1]
            lines[1] = (f"{text} {self.unit}", a)
        return lines, cur


class Choice(Item):
    focusable = True

    def __init__(self, key, label, options, value=None, help=""):
        # options: [(value, label, help)]
        self.key, self.label, self.options, self.help = key, label, options, help
        vals = [o[0] for o in options]
        self.idx = vals.index(value) if value in vals else 0

    def value(self):
        return self.options[self.idx][0]

    def render(self, width, focused):
        lines = [(f"  {self.label}", attr(C_ACCENT if focused else C_NORM, focused))]
        for i, (_v, lab, hlp) in enumerate(self.options):
            on = i == self.idx
            mark = "(o)" if on else "( )"
            a = attr(C_FOCUS) if (focused and on) else attr(C_NORM, on)
            lines.append((f"   {mark} {i + 1}. {lab}", a))
            if hlp:
                lines += [(ln, attr(C_DIM)) for ln in wrap(hlp, width - 10, "       ")]
        if self.help:
            lines += [(ln, attr(C_DIM)) for ln in wrap(self.help, width - 6, "    ")]
        return lines, None

    def handle(self, ch, ui):
        if ch in (curses.KEY_ENTER, 10, 13):
            return "next"
        if ch in (curses.KEY_RIGHT, ord(" ")):
            self.idx = (self.idx + 1) % len(self.options)
            return "handled"
        if ch == curses.KEY_LEFT:
            self.idx = (self.idx - 1) % len(self.options)
            return "handled"
        if ord("1") <= ch <= ord("9") and ch - ord("1") < len(self.options):
            self.idx = ch - ord("1")
            return "handled"
        return None


class Toggle(Item):
    focusable = True

    def __init__(self, key, label, value=False, help=""):
        self.key, self.label, self.on, self.help = key, label, bool(value), help

    def value(self):
        return self.on

    def render(self, width, focused):
        box = "[x]" if self.on else "[ ]"
        a = attr(C_FOCUS) if focused else attr(C_NORM)
        lines = [(f"  {box} {self.label}", a)]
        if self.help:
            lines += [(ln, attr(C_DIM)) for ln in wrap(self.help, width - 6, "      ")]
        return lines, None

    def handle(self, ch, ui):
        if ch in (ord(" "), curses.KEY_LEFT, curses.KEY_RIGHT):
            self.on = not self.on
            return "handled"
        if ch in (curses.KEY_ENTER, 10, 13):
            return "next"
        if ch in (ord("y"), ord("Y")):
            self.on = True
            return "handled"
        if ch in (ord("n"), ord("N")):
            self.on = False
            return "handled"
        return None


class Buttons(Item):
    focusable = True

    def __init__(self, buttons):
        # buttons: [(label, action)]
        self.buttons = buttons
        self.idx = len(buttons) - 1      # land on the rightmost (usually Next)

    def render(self, width, focused):
        parts = []
        for i, (lab, _a) in enumerate(self.buttons):
            sel = focused and i == self.idx
            parts.append((f" {lab} ", attr(C_FOCUS) if sel else attr(C_NORM, sel)))
        # One line, several attributes: emit as a list the screen can splice.
        return [("__buttons__", parts)], None

    def handle(self, ch, ui):
        if ch == curses.KEY_LEFT:
            self.idx = max(0, self.idx - 1)
            return "handled"
        if ch == curses.KEY_RIGHT:
            self.idx = min(len(self.buttons) - 1, self.idx + 1)
            return "handled"
        if ch in (curses.KEY_ENTER, 10, 13, ord(" ")):
            return self.buttons[self.idx][1]
        return None


class Screen:
    def __init__(self, title, items, subtitle="", step="", buttons=None,
                 validate=None, hint=""):
        self.title, self.subtitle, self.step = title, subtitle, step
        self.items = list(items)
        self.validate = validate
        self.hint = hint
        if buttons is None:
            buttons = [("< Back", "back"), ("Next >", "next")]
        if buttons:
            self.items += [Gap(), Buttons(buttons)]
        self.focus = next((i for i, it in enumerate(self.items) if it.focusable), 0)
        self.scroll = 0
        self.error = ""

    def focusables(self):
        return [i for i, it in enumerate(self.items) if it.focusable]

    def move_focus(self, delta):
        f = self.focusables()
        if not f:
            return
        try:
            pos = f.index(self.focus)
        except ValueError:
            pos = 0
        self.focus = f[max(0, min(len(f) - 1, pos + delta))]

    def collect(self, cfg: Config) -> None:
        for it in self.items:
            if it.key and hasattr(cfg, it.key):
                setattr(cfg, it.key, it.value())

    def check(self, cfg: Config) -> str | None:
        for it in self.items:
            err = it.validate()
            if err:
                return err
        if self.validate:
            snapshot = Config.from_dict(asdict(cfg))
            self.collect(snapshot)
            return self.validate(snapshot)
        return None


class Ui:
    def __init__(self, scr):
        self.scr = scr
        init_colors()
        scr.keypad(True)
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        try:
            curses.set_escdelay(25)
        except (AttributeError, curses.error):
            pass

    # -- primitives --

    def _put(self, win, y, x, text, a, width):
        space = width - x - 1
        if space <= 0:
            return
        try:
            win.addnstr(y, x, text, space, a)
        except curses.error:
            pass

    def _fill(self, win, y, width, a):
        try:
            win.attron(a)
            win.insstr(y, 0, " " * width)
            win.attroff(a)
        except curses.error:
            pass

    def _chrome(self, title, step, hint, error):
        h, w = self.scr.getmaxyx()
        bar = attr(C_BAR, True)
        self._fill(self.scr, 0, w, bar)
        self._put(self.scr, 0, 1, f"{APP} installer", bar, w)
        if step:
            self._put(self.scr, 0, max(1, w - len(step) - 2), step, bar, w)
        self._put(self.scr, 1, 1, title, attr(C_ACCENT, True), w)
        self._put(self.scr, 2, 1, "─" * max(0, w - 2), attr(C_DIM), w)
        if error:
            self._put(self.scr, h - 2, 1, "! " + error, attr(C_ERR, True), w)
        foot = hint or ("↑↓/Tab move · ←→ change · Enter continue · "
                        "F10 next · Esc quit")
        fa = attr(C_BAR)
        self._fill(self.scr, h - 1, w, fa)
        self._put(self.scr, h - 1, 1, foot, fa, w)

    def too_small(self):
        h, w = self.scr.getmaxyx()
        if h >= 14 and w >= 56:
            return False
        self.scr.erase()
        self._put(self.scr, 0, 0, "Terminal too small.", attr(C_ERR, True), w)
        self._put(self.scr, 1, 0, f"Need 56x14, have {w}x{h}. Resize to continue.",
                  attr(C_NORM), w)
        self.scr.refresh()
        return True

    def draw(self, screen: Screen):
        if self.too_small():
            return
        h, w = self.scr.getmaxyx()
        self.scr.erase()
        self._chrome(screen.title, screen.step, screen.hint, screen.error)
        bottom_limit = h - 3
        sub = wrap(screen.subtitle, w - 4, " ") if screen.subtitle else []
        sub = sub[:max(0, bottom_limit - 6)]
        top = 3 + len(sub)
        for i, line in enumerate(sub):
            self._put(self.scr, 3 + i, 1, line, attr(C_NORM), w)
        bottom = bottom_limit
        top = min(top, bottom)
        view = max(1, bottom - top + 1)

        blocks, y = [], 0
        for idx, it in enumerate(screen.items):
            lines, cur = it.render(w - 2, idx == screen.focus)
            blocks.append((idx, y, lines, cur))
            y += len(lines)
        total = max(1, y)

        for idx, start, lines, _cur in blocks:
            if idx == screen.focus:
                if start < screen.scroll:
                    screen.scroll = start
                elif start + len(lines) > screen.scroll + view:
                    screen.scroll = start + len(lines) - view
        screen.scroll = max(0, min(screen.scroll, max(0, total - view)))

        # Drawn straight into stdscr rather than through a pad: erase() then
        # one pass keeps the physical screen and our idea of it in step, which
        # a pad layered over an erased stdscr does not reliably do.
        for _idx, start, lines, _cur in blocks:
            for j, (text, a) in enumerate(lines):
                row = top + start + j - screen.scroll
                if row < top or row > bottom:
                    continue
                if text == "__buttons__":
                    x = 2
                    for part, pa in a:
                        self._put(self.scr, row, x, part, pa, w)
                        x += len(part) + 2
                else:
                    self._put(self.scr, row, 1, text, a, w)

        if total > view:
            mark = (f"more v ({screen.scroll + view}/{total})"
                    if screen.scroll + view < total else "end")
            self._put(self.scr, bottom + 1, max(1, w - len(mark) - 2), mark,
                      attr(C_DIM), w)

        cursor = None
        for idx, start, lines, cur in blocks:
            if idx == screen.focus and cur:
                cy = top + start + cur[0] - screen.scroll
                if top <= cy <= bottom:
                    cursor = (cy, min(w - 2, 1 + cur[1]))
        try:
            curses.curs_set(1 if cursor else 0)
        except curses.error:
            pass
        # The cursor is placed by leaving stdscr's own cursor there before the
        # refresh. curses.setsyx() also moves it, but it desynchronises the
        # physical screen from what curses thinks is on it, and the next
        # erase() then repaints nothing.
        if cursor:
            try:
                self.scr.move(*cursor)
            except curses.error:
                pass
        self.scr.noutrefresh()
        curses.doupdate()

    # -- event loop --

    def run(self, screen: Screen, cfg: Config | None = None) -> str:
        while True:
            self.draw(screen)
            try:
                ch = self.scr.getch()
            except KeyboardInterrupt:
                ch = 27
            if ch == curses.KEY_RESIZE:
                screen.scroll = 0
                continue
            if ch == -1:
                continue

            item = screen.items[screen.focus] if screen.items else None
            action = item.handle(ch, self) if item else None
            if action == "handled":
                screen.error = ""
                continue
            if action and action != "next":
                return action
            if action == "next":
                ch = curses.KEY_F10      # fall through to the validated path

            if ch in (9, curses.KEY_DOWN):
                screen.move_focus(1)
            elif ch in (curses.KEY_BTAB, 353, curses.KEY_UP):
                screen.move_focus(-1)
            elif ch == curses.KEY_NPAGE:
                screen.scroll += 5
            elif ch == curses.KEY_PPAGE:
                screen.scroll = max(0, screen.scroll - 5)
            elif ch == 27:
                if self.confirm("Quit the installer?",
                                "Nothing has been written yet unless a step said "
                                "otherwise. Your answers are lost.", default_yes=False):
                    raise Aborted()
            elif ch == curses.KEY_F5:
                return "refresh"
            elif ch in (curses.KEY_F10, curses.KEY_ENTER, 10, 13):
                err = screen.check(cfg) if cfg is not None else None
                if err:
                    screen.error = err
                    continue
                return "next"
            elif ch == curses.KEY_F9:
                return "back"
            else:
                screen.error = ""

    # -- dialogs --

    def _box(self, title, body, buttons, default=0):
        h, w = self.scr.getmaxyx()
        bw = min(max(48, len(title) + 8), w - 4)
        lines = wrap(body, bw - 4)
        bh = min(h - 4, len(lines) + 6)
        by, bx = max(0, (h - bh) // 2), max(0, (w - bw) // 2)
        idx = default
        while True:
            win = curses.newwin(bh, bw, by, bx)
            win.bkgd(" ", attr(C_NORM))
            win.border()
            self._put(win, 0, 2, f" {title} ", attr(C_ACCENT, True), bw)
            for i, ln in enumerate(lines[:bh - 5]):
                self._put(win, 2 + i, 2, ln, attr(C_NORM), bw)
            x = 2
            for i, lab in enumerate(buttons):
                self._put(win, bh - 2, x, f" {lab} ",
                          attr(C_FOCUS) if i == idx else attr(C_NORM), bw)
                x += len(lab) + 4
            try:
                curses.curs_set(0)
            except curses.error:
                pass
            win.refresh()
            ch = win.getch()
            if ch in (curses.KEY_LEFT, 9, curses.KEY_BTAB):
                idx = (idx - 1) % len(buttons)
            elif ch in (curses.KEY_RIGHT,):
                idx = (idx + 1) % len(buttons)
            elif ch in (curses.KEY_ENTER, 10, 13, ord(" ")):
                return idx
            elif ch == 27:
                return len(buttons) - 1
            elif ch in (ord("y"), ord("Y")) and len(buttons) == 2:
                return 0
            elif ch in (ord("n"), ord("N")) and len(buttons) == 2:
                return 1
            self.scr.touchwin()
            self.scr.refresh()

    def confirm(self, title, body, default_yes=True) -> bool:
        return self._box(title, body, ["Yes", "No"], 0 if default_yes else 1) == 0

    def message(self, title, body) -> None:
        self._box(title, body, ["OK"], 0)


# --- the apply phase -------------------------------------------------------


class TaskRunner:
    """Runs the plan with a live task list above a scrolling output pane."""

    def __init__(self, ui: Ui, title: str, tasks):
        self.ui, self.title, self.tasks = ui, title, tasks
        self.state = ["wait"] * len(tasks)
        self.notes = [""] * len(tasks)
        self.out: list[str] = []
        self.current = 0

    def log(self, line: str) -> None:
        for part in str(line).rstrip().split("\n"):
            self.out.append(part.replace("\t", "    "))
        del self.out[:-400]
        self.draw()

    def draw(self):
        ui, scr = self.ui, self.ui.scr
        if ui.too_small():
            return
        h, w = scr.getmaxyx()
        scr.erase()
        ui._chrome(self.title, "applying", "working — Ctrl-C aborts", "")
        y = 3
        for i, (label, _fn) in enumerate(self.tasks):
            st = self.state[i]
            mark, a = {
                "wait": ("  ", attr(C_DIM)),
                "run": ("> ", attr(C_WARN, True)),
                "ok": ("OK", attr(C_OK, True)),
                "skip": ("--", attr(C_DIM)),
                "fail": ("XX", attr(C_ERR, True)),
            }[st]
            note = f"  {self.notes[i]}" if self.notes[i] else ""
            ui._put(scr, y, 1, f"[{mark}] {label}{note}", a, w)
            y += 1
            if y >= h - 4:
                break
        ui._put(scr, y, 1, "─" * max(0, w - 2), attr(C_DIM), w)
        y += 1
        room = h - 1 - y
        for j, line in enumerate(self.out[-room:] if room > 0 else []):
            ui._put(scr, y + j, 1, line, attr(C_DIM), w)
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        scr.refresh()

    def run(self) -> bool:
        for i, (label, fn) in enumerate(self.tasks):
            self.current = i
            self.state[i] = "run"
            self.draw()
            try:
                result = fn(self.log)
                self.state[i] = "skip" if result == "skip" else "ok"
                if isinstance(result, str) and result != "skip":
                    self.notes[i] = result
            except KeyboardInterrupt:
                self.state[i] = "fail"
                self.notes[i] = "aborted"
                self.draw()
                self.log("aborted by the operator")
                return False
            except Exception as exc:                  # noqa: BLE001 — shown to the user
                self.state[i] = "fail"
                self.notes[i] = str(exc)[:60]
                self.draw()
                self.log(f"FAILED: {exc}")
                return False
            self.draw()
        return True

    def wait_key(self, prompt="Press Enter to continue"):
        h, w = self.ui.scr.getmaxyx()
        self.ui._put(self.ui.scr, h - 1, 1, prompt.ljust(w - 2), attr(C_BAR), w)
        self.ui.scr.refresh()
        while self.ui.scr.getch() not in (curses.KEY_ENTER, 10, 13, 27, ord(" ")):
            pass


def stream(cmd, log, cwd=None, env=None, timeout=1800) -> None:
    """Run a command, streaming its output into the pane. Raises on failure."""
    log("$ " + " ".join(cmd))
    merged = dict(os.environ)
    merged.setdefault("BUILDKIT_PROGRESS", "plain")   # readable build output
    merged.setdefault("DOCKER_CLI_HINTS", "false")
    if env:
        merged.update(env)
    try:
        p = subprocess.Popen(cmd, cwd=cwd, env=merged, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, bufsize=1)
    except FileNotFoundError:
        raise InstallError(f"{cmd[0]} not found")
    deadline = time.time() + timeout
    assert p.stdout is not None
    for line in p.stdout:
        log(line.rstrip())
        if time.time() > deadline:
            p.kill()
            raise InstallError(f"{cmd[0]} exceeded {timeout}s")
    rc = p.wait()
    if rc != 0:
        raise InstallError(f"{' '.join(cmd[:3])}… exited {rc}")


def priv(cmd: list[str], probe: Probe) -> list[str]:
    """Prefix with sudo when we are not root but sudo works unprompted."""
    if os.geteuid() == 0 or not probe.sudo:
        return cmd
    return ["sudo", "-n"] + cmd


def write_file(path: Path, content: str, mode: int, log, backup=True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if backup and path.exists():
        old = path.read_text()
        if old != content:
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            bak = path.with_name(path.name + f".bak-{stamp}")
            shutil.copy2(path, bak)
            log(f"kept the previous {path.name} as {bak.name}")
    tmp = path.with_name(path.name + ".new")
    tmp.write_text(content)
    os.chmod(tmp, mode)
    os.replace(tmp, path)
    log(f"wrote {path} ({oct(mode)[2:]})")


def build_plan(cfg: Config, probe: Probe, dry_run: bool):
    install = Path(cfg.install_dir)
    data = install / "data"
    tasks = []

    def t_dirs(log):
        for d in (install, data / "files", data / "postgres", install / "backups"):
            d.mkdir(parents=True, exist_ok=True)
            log(f"directory {d}")
        # The container runs as uid 10001 with every capability dropped, so it
        # cannot fix the ownership of its own blob directory at startup.
        target = data / "files"
        try:
            if os.geteuid() == 0:
                for root, dirs, files in os.walk(target):
                    for name in dirs + files:
                        os.chown(os.path.join(root, name), CONTAINER_UID, CONTAINER_UID)
                os.chown(target, CONTAINER_UID, CONTAINER_UID)
                log(f"chown {CONTAINER_UID}:{CONTAINER_UID} {target}")
            elif probe.sudo:
                stream(["sudo", "-n", "chown", "-R",
                        f"{CONTAINER_UID}:{CONTAINER_UID}", str(target)], log)
            elif target.stat().st_uid != CONTAINER_UID:
                raise InstallError(
                    f"{target} must be owned by uid {CONTAINER_UID}; re-run with sudo "
                    f"or chown it by hand")
        except PermissionError as exc:
            raise InstallError(f"cannot set ownership on {target}: {exc}")
        return None

    def t_write(log):
        write_file(install / ".env", env_file(cfg), 0o600, log)
        write_file(install / "docker-compose.yml", compose_file(cfg), 0o644, log)
        write_file(install / "INSTALL-NOTES.md", install_notes(cfg, probe), 0o644, log)
        answers = asdict(cfg)
        write_file(install / "installer-answers.json",
                   json.dumps(answers, indent=2, sort_keys=True) + "\n", 0o600, log)
        if cfg.expose == "proxy" and cfg.write_proxy_snippet:
            name, body = proxy_snippet(cfg)
            write_file(install / "reverse-proxy" / name, body, 0o644, log)
            log(f"copy that file into your {cfg.proxy_kind} configuration and reload it")
        return None

    tasks.append(("Create directories and fix ownership", t_dirs))
    tasks.append(("Write .env, compose file and notes", t_write))

    if cfg.expose == "traefik":
        def t_net(log):
            if cfg.traefik_network in probe.networks:
                log(f"network {cfg.traefik_network} already exists")
                return "skip"
            stream(["docker", "network", "create", cfg.traefik_network], log)
            return None
        tasks.append((f"Ensure the `{cfg.traefik_network}` docker network", t_net))

        if cfg.traefik_install:
            def t_traefik(log):
                tdir = Path(cfg.traefik_dir)
                acme = tdir / "acme"
                acme.mkdir(parents=True, exist_ok=True)
                os.chmod(acme, 0o700)
                write_file(tdir / "docker-compose.yml", traefik_stack(cfg), 0o644, log)
                stream(["docker", "compose", "-p", "traefik", "up", "-d"],
                       log, cwd=str(tdir))
                return None
            tasks.append(("Install and start Traefik", t_traefik))

    if cfg.start_now:
        def t_build(log):
            stream(["docker", "compose", "-p", PROJECT, "build", "app"],
                   log, cwd=str(install))
            return None

        def t_up(log):
            stream(["docker", "compose", "-p", PROJECT, "up", "-d"],
                   log, cwd=str(install))
            return None

        def t_health(log):
            deadline = time.time() + 240
            last = ""
            while time.time() < deadline:
                rc, out = run(["docker", "inspect", "-f",
                               "{{.State.Status}} {{if .State.Health}}"
                               "{{.State.Health.Status}}{{end}}",
                               f"{PROJECT}-app"], timeout=15)
                if rc != 0:
                    raise InstallError(f"container {PROJECT}-app is gone: {out}")
                if out != last:
                    log(f"{PROJECT}-app: {out}")
                    last = out
                if "healthy" in out and "unhealthy" not in out:
                    return None
                if out.startswith("exited") or out.startswith("dead"):
                    _rc, logs = run(["docker", "logs", "--tail", "40",
                                     f"{PROJECT}-app"], timeout=20)
                    log(logs)
                    raise InstallError("the app container exited — see the log above")
                time.sleep(3)
            _rc, logs = run(["docker", "logs", "--tail", "40", f"{PROJECT}-app"],
                            timeout=20)
            log(logs)
            raise InstallError("timed out waiting for a healthy container")

        def t_verify(log):
            body = ""
            if cfg.publishes_port():
                url = f"http://127.0.0.1:{cfg.port}/healthz"
                try:
                    with urllib.request.urlopen(url, timeout=10) as r:
                        body = r.read().decode().strip()
                except (urllib.error.URLError, OSError) as exc:
                    raise InstallError(f"{url}: {exc}")
                log(f"{url} -> {body}")
            else:
                rc, body = run(["docker", "exec", f"{PROJECT}-app", "wget", "-qO-",
                                f"http://127.0.0.1:{CONTAINER_PORT}/healthz"],
                               timeout=20)
                if rc != 0:
                    raise InstallError(f"/healthz inside the container: {body}")
                log(f"/healthz -> {body.strip()}")
            _rc, logs = run(["docker", "logs", "--tail", "200", f"{PROJECT}-app"],
                            timeout=20)
            for line in logs.splitlines():
                if "admin bootstrap" in line or "migration" in line:
                    log(line)
            return body.strip() or None

        tasks.append(("Build the application image", t_build))
        tasks.append(("Start the stack", t_up))
        tasks.append(("Wait for a healthy container", t_health))
        tasks.append(("Verify /healthz and the first admin", t_verify))

    if cfg.backup_cron:
        def t_cron(log):
            script = install / "backup.sh"
            write_file(script, backup_script(cfg), 0o755, log)
            cron = Path("/etc/cron.d/pyxis-backup")
            body = ("# Nightly Pyxis database dump, installed by install.py.\n"
                    "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:"
                    "/usr/bin:/sbin:/bin\n"
                    f"17 3 * * * root {script} >/dev/null 2>&1\n")
            if os.geteuid() != 0:
                log(f"not root: install this yourself as {cron}:")
                log(body)
                return "cron entry not installed"
            write_file(cron, body, 0o644, log)
            return None
        tasks.append(("Install the nightly database backup", t_cron))

    if dry_run:
        preview = []

        def make_preview(label, path, body):
            def fn(log):
                log(f"--- would write {path} ---")
                log(body)
                return None
            return (label, fn)

        preview.append(make_preview("Preview .env", install / ".env", env_file(cfg)))
        preview.append(make_preview("Preview docker-compose.yml",
                                    install / "docker-compose.yml", compose_file(cfg)))
        if cfg.expose == "proxy":
            name, body = proxy_snippet(cfg)
            preview.append(make_preview(f"Preview {name}",
                                        install / "reverse-proxy" / name, body))
        if cfg.expose == "traefik" and cfg.traefik_install:
            preview.append(make_preview("Preview traefik compose",
                                        Path(cfg.traefik_dir) / "docker-compose.yml",
                                        traefik_stack(cfg)))
        preview.append(make_preview("Preview INSTALL-NOTES.md",
                                    install / "INSTALL-NOTES.md",
                                    install_notes(cfg, probe)))
        return preview

    return tasks


# --- docker bootstrap ------------------------------------------------------

DOCKER_HINTS = {
    "debian": (
        "Debian/Ubuntu — Docker's own repository (the distro's docker.io is\n"
        "usually too old for `docker compose`):\n\n"
        "  sudo apt-get update && sudo apt-get install -y ca-certificates curl\n"
        "  sudo install -m 0755 -d /etc/apt/keyrings\n"
        "  sudo curl -fsSL https://download.docker.com/linux/debian/gpg \\\n"
        "       -o /etc/apt/keyrings/docker.asc\n"
        "  echo \"deb [signed-by=/etc/apt/keyrings/docker.asc] \\\n"
        "    https://download.docker.com/linux/debian $(. /etc/os-release && \\\n"
        "    echo $VERSION_CODENAME) stable\" | \\\n"
        "    sudo tee /etc/apt/sources.list.d/docker.list\n"
        "  sudo apt-get update && sudo apt-get install -y docker-ce docker-ce-cli \\\n"
        "       containerd.io docker-buildx-plugin docker-compose-plugin\n"),
    "rhel": (
        "Fedora/RHEL:\n\n"
        "  sudo dnf -y install dnf-plugins-core\n"
        "  sudo dnf config-manager --add-repo \\\n"
        "       https://download.docker.com/linux/fedora/docker-ce.repo\n"
        "  sudo dnf -y install docker-ce docker-ce-cli containerd.io \\\n"
        "       docker-buildx-plugin docker-compose-plugin\n"
        "  sudo systemctl enable --now docker\n"),
    "arch": (
        "Arch:\n\n"
        "  sudo pacman -S --needed docker docker-buildx docker-compose\n"
        "  sudo systemctl enable --now docker\n"),
    "suse": (
        "openSUSE:\n\n"
        "  sudo zypper install docker docker-compose\n"
        "  sudo systemctl enable --now docker\n"),
    "alpine": (
        "Alpine:\n\n"
        "  sudo apk add docker docker-cli-compose\n"
        "  sudo rc-update add docker default && sudo service docker start\n"),
}


def install_docker(ui: Ui, probe: Probe) -> None:
    """Run Docker's convenience script, with the operator's explicit consent."""
    if not probe.privileged:
        ui.message("Root required",
                   "Installing Docker needs root. Re-run this installer with "
                   "sudo, or install Docker yourself and press F5 to re-check.")
        return
    ok = ui.confirm(
        "Install Docker Engine?",
        "This downloads https://get.docker.com and runs it as root. It is "
        "Docker's own convenience script: it adds Docker's repository and "
        "installs docker-ce with the compose plugin, changing your package "
        "sources. Continue?", default_yes=False)
    if not ok:
        return

    script = Path("/tmp/get-docker.sh")

    def fetch(log):
        log("downloading https://get.docker.com")
        with urllib.request.urlopen("https://get.docker.com", timeout=60) as r:
            body = r.read().decode()
        if "docker" not in body[:4000].lower():
            raise InstallError("that did not look like the Docker install script")
        script.write_text(body)
        os.chmod(script, 0o700)
        return f"{len(body)} bytes"

    def install(log):
        stream(priv(["sh", str(script)], probe), log, timeout=1800)
        return None

    def enable(log):
        if shutil.which("systemctl"):
            stream(priv(["systemctl", "enable", "--now", "docker"], probe), log)
        else:
            log("no systemd here — start the docker daemon the way your init does")
        return None

    runner = TaskRunner(ui, "Installing Docker Engine", [
        ("Download get.docker.com", fetch),
        ("Run the installer (this takes a few minutes)", install),
        ("Enable and start the daemon", enable),
    ])
    ok = runner.run()
    runner.log("")
    runner.log("done — press Enter to go back to the check" if ok else
               "install failed; you can still install Docker by hand and press F5")
    runner.wait_key()


# --- wizard steps ----------------------------------------------------------


def s_welcome(cfg: Config, probe: Probe, ui: Ui) -> Screen:
    lines = [
        Static(f"This wizard installs {APP} — self-hosted file sharing where the "
               "server cannot read what it stores — as a Docker Compose stack: "
               "the app, a PostgreSQL 16 database, and whatever front door you "
               "pick.", C_NORM),
        Gap(),
        Static("It will ask about, in order:", C_NORM),
        Static("Docker · where to install · how the site is reached (Traefik, "
               "another reverse proxy, or a published port) · the domain · an "
               "optional custom port · the first administrator · secrets, "
               "limits and optional single sign-on.", C_DIM, indent="  "),
        Gap(),
        Static("Nothing is written or started until you confirm on the review "
               "screen at the end.", C_OK),
        Gap(),
        Static("This host", C_ACCENT, bold=True),
        Static(f"  {probe.distro}", C_DIM),
        Static(f"  running as {current_user()}"
               f"{' (root)' if probe.root else ''}"
               f"{'' if probe.root else ' — sudo: ' + ('yes' if probe.sudo else 'no')}",
               C_DIM),
        Static(f"  {human_bytes(probe.disk_free)} free where the data will live",
               C_DIM if probe.disk_free > 5 * GIB else C_WARN),
    ]
    if not probe.privileged:
        lines += [Gap(), Static(
            "You are not root and sudo does not work without a password. "
            "Creating /srv/docker/pyxis, chowning the blob directory to uid "
            f"{CONTAINER_UID} and talking to the Docker socket may all fail. "
            "Consider quitting and re-running with sudo.", C_WARN)]
    return Screen(f"Welcome to the {APP} installer", lines,
                  buttons=[("Quit", "quit"), ("Next >", "next")])


def s_docker(cfg: Config, probe: Probe, ui: Ui) -> Screen:
    items = []

    def row(ok, good, bad):
        items.append(Static(("  OK  " if ok else "  !!  ") + (good if ok else bad),
                            C_OK if ok else C_ERR))

    row(bool(probe.docker), probe.docker or "", "Docker engine not found")
    row(bool(probe.compose), probe.compose or "",
        "The `docker compose` plugin is missing (v1 `docker-compose` is not enough)")
    row(probe.daemon_ok, "The Docker daemon answers",
        f"Cannot talk to the daemon: {probe.daemon_err or 'unknown error'}")
    if probe.docker and not probe.daemon_ok and not probe.root:
        items.append(Static(
            "  You are not root and " +
            ("are" if probe.in_docker_group else "are not") +
            " in the `docker` group. Membership only takes effect in a new "
            "login session — log out and back in, or run this with sudo.", C_DIM))

    if probe.docker_ready:
        items += [Gap(), Static("Docker is ready. Continue.", C_OK)]
        buttons = [("< Back", "back"), ("Re-check", "refresh"), ("Next >", "next")]
    else:
        items += [
            Gap(),
            Static("How would you like to fix this?", C_ACCENT, bold=True),
            Static(DOCKER_HINTS.get(probe.distro_family,
                                    "See https://docs.docker.com/engine/install/\n"
                                    "for your distribution."), C_DIM, pre=True,
                   indent="  "),
            Gap(),
            Static("The installer can also run Docker's own convenience script "
                   "(get.docker.com) for you — it needs root and network access, "
                   "and it adds Docker's package repository.", C_NORM),
        ]
        buttons = [("< Back", "back"), ("Install Docker", "install-docker"),
                   ("Re-check", "refresh"), ("Next >", "next")]

    def check(_c):
        if not probe.docker_ready and not DRY_RUN:
            return ("Docker is not usable yet — install it, then press Re-check "
                    "(F5). Nothing later in the wizard can work without it.")
        return None

    return Screen("Docker", items,
                  subtitle="Pyxis runs as two containers, so a working Docker "
                           "with the compose plugin is the one hard requirement.",
                  buttons=buttons, validate=check,
                  hint="F5 re-check · ←→ pick a button · Enter activate · Esc quit")


def s_location(cfg: Config, probe: Probe, ui: Ui) -> Screen:
    repo = Text("repo_dir", "Source directory (the build context)", cfg.repo_dir,
                help="Must contain the Dockerfile. Defaults to this checkout; "
                     "keep it — upgrades are `git pull` here plus a rebuild.")
    inst = Text("install_dir", "Install directory", cfg.install_dir,
                help="Holds .env, the generated compose file, data/files "
                     "(encrypted blobs) and data/postgres (the database).")

    def check(c):
        if not Path(c.repo_dir).expanduser().is_dir():
            return f"{c.repo_dir}: not a directory"
        if not (Path(c.repo_dir).expanduser() / "Dockerfile").is_file():
            return f"no Dockerfile in {c.repo_dir}"
        if not c.install_dir.startswith("/"):
            return "the install directory must be an absolute path"
        existing = Path(c.install_dir) / ".env"
        if existing.exists() and not getattr(check, "warned", False):
            check.warned = True
            return (f"{existing} already exists — continuing rewrites it "
                    "(a timestamped backup is kept). Press Enter again to accept.")
        return None

    return Screen("Where things go", [repo, inst],
                  subtitle="The source tree is built from where it is; only the "
                           "runtime files and data are copied to the install "
                           "directory.",
                  validate=check)


def s_expose(cfg: Config, probe: Probe, ui: Ui) -> Screen:
    has_traefik = "traefik" in (probe.networks or []) or Path("/srv/docker/traefik").exists()
    choice = Choice("expose", "How will browsers reach this instance?", [
        ("traefik", "Traefik" + (" (already on this host)" if has_traefik else ""),
         "Container labels, an external docker network, automatic Let's Encrypt "
         "certificates. No port is published on the host."),
        ("proxy", "Another reverse proxy on this host (nginx, Caddy, Apache)",
         "The container publishes a port on 127.0.0.1 and the installer writes a "
         "matching site configuration for you to install."),
        ("direct", "Nothing in front — publish the port directly",
         "Simplest, and plain HTTP unless you terminate TLS elsewhere. Fine on a "
         "private network; on the open internet the login cookie and every share "
         "link travel in the clear."),
    ], cfg.expose)
    return Screen("Front door", [choice],
                  subtitle="This decides the compose file: Traefik labels, a "
                           "published port, or both networks.")


def s_traefik(cfg: Config, probe: Probe, ui: Ui) -> Screen:
    known = probe.networks or []
    net_help = ("The external docker network Traefik shares with its backends."
                + (f" Existing: {', '.join(known[:6])}" if known else ""))
    items = [
        Text("domain", "Domain", cfg.domain or "",
             help="The hostname in the router rule and the certificate. Its DNS "
                  "must already point at this host, or the ACME challenge fails.",
             validator=lambda v: None if valid_host(v) else "not a hostname"),
        Gap(),
        Text("traefik_network", "Traefik docker network", cfg.traefik_network,
             help=net_help, width=24),
        Text("traefik_entrypoint", "HTTPS entrypoint", cfg.traefik_entrypoint,
             help="The name of Traefik's :443 entrypoint.", width=24),
        Text("traefik_certresolver", "Certificate resolver", cfg.traefik_certresolver,
             help="The ACME resolver defined in your Traefik configuration.",
             width=24),
        Toggle("traefik_redirect", "Also add an HTTP -> HTTPS redirect router",
               cfg.traefik_redirect,
               help="Skip it if Traefik already redirects globally."),
        Gap(),
        Toggle("traefik_install", "I do not have Traefik yet — install it too",
               cfg.traefik_install,
               help="Writes a minimal Traefik stack (TLS-ALPN Let's Encrypt, "
                    "docker provider, ports 80 and 443) and starts it."),
        Text("acme_email", "Let's Encrypt account e-mail", cfg.acme_email,
             help="Only used when the installer sets Traefik up for you."),
    ]

    def check(c):
        if not valid_host(c.domain):
            return "a domain is required for a Traefik router"
        if not c.traefik_network.strip():
            return "the network name cannot be empty"
        if c.traefik_install and not EMAIL_RE.match(c.acme_email.strip()):
            return "Let's Encrypt needs a valid account e-mail"
        if not c.traefik_install and known and c.traefik_network not in known:
            return (f"no docker network named {c.traefik_network!r} — the "
                    "installer will create it; press Enter again to accept")
        return None

    return Screen("Traefik", items,
                  subtitle="Pyxis joins Traefik's network and asks for a "
                           "certificate through the labels below.",
                  validate=check)


def s_proxy(cfg: Config, probe: Probe, ui: Ui) -> Screen:
    port = Number("port", "Host port", cfg.port, lo=1, hi=65535,
                  help="The container listens on 8080 inside; this is the port "
                       "your proxy connects to on the host.")
    items = [
        Choice("proxy_kind", "Which proxy?", [
            ("nginx", "nginx", ""),
            ("caddy", "Caddy", "Obtains certificates itself."),
            ("apache", "Apache httpd", "Needs mod_proxy and mod_headers."),
        ], cfg.proxy_kind),
        Gap(),
        Text("domain", "Domain", cfg.domain,
             help="The name the proxy serves and the one in the certificate.",
             validator=lambda v: None if valid_host(v) else "not a hostname"),
        Toggle("https", "The proxy serves HTTPS", cfg.https,
               help="Leave on unless you are deliberately serving plain HTTP: "
                    "it sets COOKIE_SECURE, which keeps the session cookie off "
                    "unencrypted connections."),
        Gap(),
        Toggle("custom_port", "Use a custom host port", cfg.custom_port,
               help="Off means 8080. Change it if something else already has "
                    "that port."),
        port,
        Toggle("bind_all", "Publish on all interfaces instead of 127.0.0.1",
               cfg.bind_all,
               help="Leave off. With the proxy on this host, binding to "
                    "localhost keeps the unencrypted port off the network."),
        Gap(),
        Toggle("write_proxy_snippet", "Write a ready site configuration",
               cfg.write_proxy_snippet,
               help="Saved under the install directory. The installer never "
                    "edits your proxy's configuration itself."),
    ]

    def check(c):
        p = c.port if c.custom_port else 8080
        if not valid_host(c.domain):
            return "a domain is required"
        if not port_free(p, "127.0.0.1") and not _our_container_holds(p):
            return f"port {p} is already in use on this host"
        return None

    return Screen("Reverse proxy", items,
                  subtitle="The container publishes a plain-HTTP port; your "
                           "proxy terminates TLS and forwards to it.",
                  validate=check)


def s_direct(cfg: Config, probe: Probe, ui: Ui) -> Screen:
    ip = primary_ip()
    port = Number("port", "Host port", cfg.port, lo=1, hi=65535,
                  help="Published on every interface. 80 and 443 need root.")
    items = [
        Static("Without a proxy there is no TLS. Files are still encrypted in "
               "the browser before upload, so their contents stay private — but "
               "the session cookie, the login form and the share links "
               "themselves travel in the clear. Use this on a trusted network, "
               "or put TLS in front later.", C_WARN),
        Gap(),
        Text("domain", "Hostname or IP browsers will use", cfg.domain or ip,
             help="Used for the printed URL and, if you enable it, the OIDC "
                  "redirect. An IP address is fine here.",
             validator=lambda v: None if valid_host(v) else "not a hostname or IP"),
        Toggle("custom_port", "Use a custom port", cfg.custom_port,
               help="Off means 8080."),
        port,
        Toggle("https", "Something else already terminates TLS for this address",
               cfg.https,
               help="Turn on only if a load balancer or tunnel in front of this "
                    "host serves HTTPS; it sets COOKIE_SECURE."),
    ]

    def check(c):
        p = c.port if c.custom_port else 8080
        if not valid_host(c.domain):
            return "a hostname or IP is required"
        if p < 1024 and os.geteuid() != 0:
            return f"port {p} is privileged; docker needs root to publish it"
        if not port_free(p) and not _our_container_holds(p):
            return f"port {p} is already in use on this host"
        return None

    return Screen("Direct port", items,
                  subtitle="The container publishes its port on the host and "
                           "answers browsers itself.",
                  validate=check)


def _our_container_holds(port: int) -> bool:
    """A re-install finds its own container on the port; that is not a clash."""
    rc, out = run(["docker", "ps", "--filter", f"name={PROJECT}-app",
                   "--format", "{{.Ports}}"], timeout=10)
    return rc == 0 and f":{port}->" in out


def s_admin(cfg: Config, probe: Probe, ui: Ui) -> Screen:
    user = Text("admin_user", "Username", cfg.admin_user, width=28,
                help="Created on first startup as super-admin.")
    pw = Password("admin_pass", "Password", cfg.admin_pass, generate=True,
                  help=f"At least {MIN_PASSWORD_LEN} characters — the app "
                       "enforces the same floor. F4 shows it, F6 generates one.")
    again = Password(None, "Password again", cfg.admin_pass)
    items = [
        Static("This account is created only if the database has no super-admin "
               "yet. On an existing installation the bootstrap does nothing — it "
               "never resets or promotes an account, so changing the password "
               "here later has no effect. Use the UI for that.", C_DIM),
        Gap(), user, pw, again,
        Gap(),
        Static("Passwords are stored as Argon2id. The value also lands in .env "
               "in plain text, which is why that file is written 0600 — you can "
               "empty ADMIN_PASSWORD there once the account exists.", C_DIM),
    ]

    def check(c):
        if not c.admin_user.strip() or " " in c.admin_user.strip():
            return "a username without spaces is required"
        problem = password_problem(c.admin_pass)
        if problem:
            return "password: " + problem
        if pw.value() != again.value():
            return "the two passwords differ"
        return None

    return Screen("First administrator", items, validate=check)


def s_secrets(cfg: Config, probe: Probe, ui: Ui) -> Screen:
    hint = {
        "traefik": "the network Traefik reaches this container from",
        "proxy": "the docker bridge your proxy's requests arrive over",
        "direct": "leave empty: clients connect directly, so no forwarded "
                  "header should be believed",
    }[cfg.expose]
    items = [
        Static("Both values are generated. Keep them — the wizard shows them "
               "once here and then writes them to .env (0600).", C_NORM),
        Gap(),
        Password("postgres_password", "PostgreSQL password", cfg.postgres_password,
                 generate=True, help="Used by the app container only; the "
                                     "database is not published anywhere."),
        Password("file_key", "FILE_ENCRYPTION_KEY (32-byte hex)", cfg.file_key,
                 help="Protects short secrets in the settings table, principally "
                      "the OIDC client secret. It does NOT protect uploads: "
                      "those are encrypted in the browser under keys the server "
                      "never sees. Lose it and you lose the stored OIDC secret."),
        Gap(),
        Text("trusted_cidrs", "TRUSTED_PROXY_CIDRS", cfg.trusted_cidrs,
             help=f"Whose X-Forwarded-For to believe — {hint}. Too wide lets a "
                  "forged header dodge the rate limiter; empty behind a proxy "
                  "makes every visitor share one bucket, so one person guessing "
                  "a share password locks out everybody.",
             validator=check_cidrs, width=34),
    ]

    def check(c):
        if len(c.file_key) != 64 or not re.fullmatch(r"[0-9a-fA-F]{64}", c.file_key):
            return "FILE_ENCRYPTION_KEY must be exactly 64 hex characters"
        if not c.postgres_password:
            return "the database password cannot be empty"
        if "$" in c.postgres_password or "$" in c.admin_pass:
            return "avoid '$' in passwords: Compose interpolates it out of .env"
        if c.expose != "direct" and not c.trusted_cidrs.strip():
            return ("behind a proxy this must be set — the compose file refuses "
                    "to start without it")
        return None

    return Screen("Secrets and proxy trust", items, validate=check)


def s_limits(cfg: Config, probe: Probe, ui: Ui) -> Screen:
    items = [
        Number("max_upload_mb", "Per-file upload limit", cfg.max_upload_mb,
               lo=1, hi=1024 * 64, unit="MiB",
               help="The ciphertext is slightly larger than the file: a 16-byte "
                    "tag per 64 KiB chunk plus a manifest. Any proxy in front "
                    "needs a body limit at least this high."),
        Gap(),
        Number("quota_user_gb", "Default quota per user", cfg.quota_user_gb,
               lo=0, hi=1024 * 64, unit="GiB",
               help="0 means unlimited. Only the INITIAL default: once an admin "
                    "saves quotas in /admin/settings the database wins."),
        Number("quota_user_files", "Active files per user", cfg.quota_user_files,
               lo=0, hi=10_000_000, unit="files"),
        Gap(),
        Number("quota_total_gb", "Instance-wide ceiling", cfg.quota_total_gb,
               lo=0, hi=1024 * 1024, unit="GiB", help="0 means unlimited."),
        Number("disk_min_free_gb", "Refuse uploads below", cfg.disk_min_free_gb,
               lo=0, hi=1024 * 64, unit="GiB free",
               help="A floor that keeps the volume from filling completely."),
    ]
    free = human_bytes(probe.disk_free)
    return Screen("Limits and quotas", items,
                  subtitle=f"{free} free where the data will live. Every value "
                           "here can be changed later in .env or the admin UI.")


def s_sso(cfg: Config, probe: Probe, ui: Ui) -> Screen:
    items = [
        Static("Optional. Single sign-on is additive: enabling it does not "
               "disable password login, and you can configure all of this later "
               "in /admin/settings instead.", C_DIM),
        Gap(),
        Toggle("oidc_enabled", "Configure an OIDC provider now", cfg.oidc_enabled),
        Text("oidc_issuer", "Issuer URL", cfg.oidc_issuer,
             help="e.g. https://auth.example.com — discovery is fetched from "
                  "its /.well-known/openid-configuration."),
        Text("oidc_client_id", "Client ID", cfg.oidc_client_id),
        Password("oidc_client_secret", "Client secret", cfg.oidc_client_secret,
                 help="Stored encrypted under FILE_ENCRYPTION_KEY. F4 shows it."),
        Text("oidc_allowed_domain", "Restrict to e-mail domain (optional)",
             cfg.oidc_allowed_domain, width=28),
        Gap(),
        Static("Redirect URI to register with the provider, byte for byte:", C_NORM),
        Static(f"  {cfg.oidc_redirect()}", C_ACCENT, bold=True),
        Static("It follows the domain you chose. Change the domain later and "
               "this has to change with it, at the provider and in .env.", C_DIM),
    ]

    def check(c):
        if not c.oidc_enabled:
            return None
        if not c.oidc_issuer.startswith("https://"):
            return "the issuer must be an https:// URL"
        if not c.oidc_client_id.strip() or not c.oidc_client_secret:
            return "client ID and secret are both required"
        if "$" in c.oidc_client_secret:
            return ("a '$' in the secret is eaten by Compose interpolation — "
                    "leave SSO off here and paste it into /admin/settings")
        return None

    return Screen("Single sign-on (optional)", items, validate=check)


def s_extras(cfg: Config, probe: Probe, ui: Ui) -> Screen:
    items = [
        Toggle("backup_cron", "Install a nightly database backup", cfg.backup_cron,
               help="Writes backup.sh and a /etc/cron.d entry that dumps "
                    "PostgreSQL at 03:17 and keeps 14 days. The encrypted blobs "
                    "are not included — back up data/files with your usual file "
                    "backup."),
        Gap(),
        Toggle("start_now", "Build the image and start the stack now",
               cfg.start_now,
               help="Off writes the configuration and stops, leaving "
                    "`docker compose up -d --build` to you. The first build "
                    "compiles the Go binary and takes a few minutes."),
    ]
    return Screen("Finishing touches", items)


def s_review(cfg: Config, probe: Probe, ui: Ui) -> Screen:
    exposure = {
        "traefik": f"Traefik on network `{cfg.traefik_network}`"
                   f" (entrypoint {cfg.traefik_entrypoint}, resolver "
                   f"{cfg.traefik_certresolver})"
                   + (", Traefik itself installed too" if cfg.traefik_install else ""),
        "proxy": f"{cfg.proxy_kind} on this host -> "
                 f"{'0.0.0.0' if cfg.bind_all else '127.0.0.1'}:{cfg.port}",
        "direct": f"published on port {cfg.port} (no TLS in front)"
                  if not cfg.https else f"published on port {cfg.port}",
    }[cfg.expose]
    rows = [
        ("URL", cfg.base_url()),
        ("Exposure", exposure),
        ("Install directory", cfg.install_dir),
        ("Source", cfg.repo_dir),
        ("Administrator", cfg.admin_user),
        ("Upload limit", f"{cfg.max_upload_mb} MiB per file"),
        ("User quota", "unlimited" if cfg.quota_user_gb == 0
         else f"{cfg.quota_user_gb} GiB / {cfg.quota_user_files} files"),
        ("Trusted proxies", cfg.trusted_cidrs or "(none — direct connections)"),
        ("Single sign-on", cfg.oidc_issuer if cfg.oidc_enabled else "not configured"),
        ("Nightly backup", "yes" if cfg.backup_cron else "no"),
    ]
    width = max(len(k) for k, _ in rows)
    items = [Static("The installer will now:", C_ACCENT, bold=True)]
    will = [
        f"create {cfg.install_dir}/data/{{files,postgres}} and chown files to "
        f"uid {CONTAINER_UID}",
        "write .env (0600), docker-compose.yml, INSTALL-NOTES.md and "
        "installer-answers.json",
    ]
    if cfg.expose == "traefik":
        will.append(f"ensure the `{cfg.traefik_network}` docker network exists")
    if cfg.traefik_install:
        will.append(f"write and start a Traefik stack in {cfg.traefik_dir}")
    if cfg.expose == "proxy" and cfg.write_proxy_snippet:
        will.append(f"write the {cfg.proxy_kind} site file (you install it yourself)")
    if cfg.start_now:
        will.append("build the image, start both containers and wait for /healthz")
    if cfg.backup_cron:
        will.append("install backup.sh and /etc/cron.d/pyxis-backup")
    items += [Static("  - " + w, C_NORM) for w in will]
    items += [Gap(), Static("Settings", C_ACCENT, bold=True)]
    items += [Static(f"  {k.ljust(width)}   {v}", C_NORM) for k, v in rows]
    items += [Gap(),
              Static("Nothing above has happened yet. Back to change anything.",
                     C_DIM)]
    return Screen("Review", items,
                  buttons=[("< Back", "back"), ("Install", "next")],
                  hint="←→ pick a button · Enter activate · Esc quit")


STEPS = [
    ("welcome", lambda c: True, s_welcome),
    ("docker", lambda c: True, s_docker),
    ("location", lambda c: True, s_location),
    ("expose", lambda c: True, s_expose),
    ("traefik", lambda c: c.expose == "traefik", s_traefik),
    ("proxy", lambda c: c.expose == "proxy", s_proxy),
    ("direct", lambda c: c.expose == "direct", s_direct),
    ("admin", lambda c: True, s_admin),
    ("secrets", lambda c: True, s_secrets),
    ("limits", lambda c: True, s_limits),
    ("sso", lambda c: True, s_sso),
    ("extras", lambda c: True, s_extras),
    ("review", lambda c: True, s_review),
]


# --- wizard driver ---------------------------------------------------------

_auto: dict[str, str] = {}


def suggest_cidrs(cfg: Config) -> str:
    if cfg.expose == "direct":
        return ""
    if cfg.expose == "traefik":
        nets = network_subnets(cfg.traefik_network)
        if nets:
            return ", ".join(nets)
    # The proxy runs on the host, so requests arrive from the compose bridge's
    # gateway. Compose allocates that subnet dynamically inside 172.16/12.
    return "172.16.0.0/12"


def seed_defaults(cfg: Config, probe: Probe, step: str) -> None:
    if step == "direct" and "https" not in _auto:
        # Nothing in front means plain HTTP unless the operator says otherwise;
        # seeded once so a deliberate answer survives going back and forth.
        cfg.https = False
        _auto["https"] = "seeded"
    if step == "secrets":
        suggestion = suggest_cidrs(cfg)
        if not cfg.trusted_cidrs.strip() or cfg.trusted_cidrs == _auto.get("cidrs"):
            cfg.trusted_cidrs = suggestion
        _auto["cidrs"] = suggestion


def normalize(cfg: Config) -> None:
    cfg.domain = cfg.domain.strip().lower().rstrip(".")
    cfg.repo_dir = str(Path(cfg.repo_dir).expanduser().resolve()) \
        if cfg.repo_dir else cfg.repo_dir
    cfg.install_dir = os.path.normpath(cfg.install_dir.strip())
    if not cfg.custom_port:
        cfg.port = 8080
    if cfg.expose == "direct":
        # Nothing in front means the container itself must answer the network,
        # so binding to loopback would publish the port to no one.
        cfg.bind_all = True
    cfg.trusted_cidrs = ", ".join(
        p for p in re.split(r"[,\s]+", cfg.trusted_cidrs.strip()) if p)
    cfg.admin_user = cfg.admin_user.strip()
    cfg.file_key = cfg.file_key.strip().lower()
    for attribute in ("oidc_issuer", "oidc_client_id", "oidc_allowed_domain"):
        setattr(cfg, attribute, getattr(cfg, attribute).strip())
    cfg.oidc_issuer = cfg.oidc_issuer.rstrip("/")


def wizard(ui: Ui, cfg: Config, probe: Probe) -> Probe:
    i, direction = 0, 1
    while 0 <= i < len(STEPS):
        name, applies, build = STEPS[i]
        if not applies(cfg):
            i += direction
            continue
        active = [s for s in STEPS if s[1](cfg)]
        position = [s[0] for s in active].index(name) + 1
        seed_defaults(cfg, probe, name)
        screen = build(cfg, probe, ui)
        screen.step = f"step {position}/{len(active)}"
        action = ui.run(screen, cfg)

        if action == "quit":
            raise Aborted()
        if action in ("refresh", "install-docker"):
            # Both rebuild this screen, so keep whatever was typed into it.
            screen.collect(cfg)
            normalize(cfg)
            if action == "install-docker":
                install_docker(ui, probe)
            probe = probe_host(cfg.install_dir)
            continue
        if action == "back":
            screen.collect(cfg)          # keep edits, skip validation
            normalize(cfg)
            direction = -1
            i = max(0, i - 1)
            continue
        screen.collect(cfg)
        normalize(cfg)
        direction = 1
        i += 1
    return probe


def final_screen(ui: Ui, cfg: Config, ok: bool, dry_run: bool) -> list[str]:
    """Show the outcome and return the same summary as plain lines."""
    out: list[str] = []
    if dry_run:
        title = "Dry run complete"
        out.append("Dry run: nothing was written or started.")
    elif ok and cfg.start_now:
        title = f"{APP} is installed"
        out += [
            f"{APP} is running at {cfg.base_url()}",
            f"Sign in as {cfg.admin_user!r} with the password you set.",
            "",
            f"Configuration and data: {cfg.install_dir}",
            f"Notes and everyday commands: {cfg.install_dir}/INSTALL-NOTES.md",
        ]
    elif ok:
        title = f"{APP} is configured"
        out += [
            "The configuration is written; nothing has been started. Bring it up with:",
            "",
            f"  cd {cfg.install_dir} && docker compose -p {PROJECT} up -d --build",
            "",
            f"It will then answer at {cfg.base_url()} — sign in as "
            f"{cfg.admin_user!r}.",
            f"Notes and everyday commands: {cfg.install_dir}/INSTALL-NOTES.md",
        ]
    else:
        title = "Installation did not finish"
        out += [
            "A step failed — the output above says which.",
            f"Fix it and re-run this installer; your answers are in "
            f"{cfg.install_dir}/installer-answers.json and can be replayed with",
            f"  sudo ./install.py --answers {cfg.install_dir}/installer-answers.json",
        ]

    if ok and not dry_run:
        out.append("")
        out.append("Next:")
        if cfg.expose == "traefik":
            out.append(f"  - Point {cfg.domain} at this host. Traefik issues the "
                       "certificate on the first request, which can take a minute.")
            if cfg.traefik_install:
                out.append(f"  - Traefik lives in {cfg.traefik_dir}; its ACME "
                           "storage is acme/acme.json — back that up.")
        elif cfg.expose == "proxy":
            name = proxy_snippet(cfg)[0]
            out.append(f"  - Install {cfg.install_dir}/reverse-proxy/{name} into "
                       f"{cfg.proxy_kind}, check the certificate paths, reload.")
            out.append(f"  - Confirm the body-size limit is at least "
                       f"{cfg.max_upload_mb} MiB or large uploads fail at the proxy.")
        else:
            out.append(f"  - Only port {cfg.port} needs to be reachable; nothing "
                       "here terminates TLS.")
        if cfg.oidc_enabled:
            out.append(f"  - Register the redirect URI exactly: {cfg.oidc_redirect()}")
        else:
            out.append("  - Single sign-on can be configured later in "
                       "/admin/settings.")
        out.append(f"  - Back up {cfg.install_dir}/.env. Losing "
                   "FILE_ENCRYPTION_KEY loses the stored OIDC secret.")
        out.append("  - Uploads are encrypted in the browser: no admin, and no "
                   "database dump, can read a stored file.")

    items = [Static(line if line else " ",
                    C_OK if line.startswith(APP) else C_NORM)
             for line in out]
    ui.run(Screen(title, items, buttons=[("Finish", "next")],
                  hint="Enter to leave the installer"), None)
    return out


# --- non-interactive path --------------------------------------------------


def run_plainly(cfg: Config, probe: Probe, dry_run: bool) -> bool:
    """Apply a saved answer file without curses (for scripted re-runs)."""
    plan = build_plan(cfg, probe, dry_run)
    for label, fn in plan:
        print(f"==> {label}")
        try:
            note = fn(lambda line: print(
                "\n".join("    " + part for part in str(line).rstrip().split("\n"))))
        except Exception as exc:                       # noqa: BLE001
            print(f"!!! {label}: {exc}", file=sys.stderr)
            return False
        if note and note != "skip":
            print(f"    ({note})")
    return True


def check_answers(cfg: Config) -> str | None:
    """The validations the wizard would have run, for the scripted path."""
    if not (Path(cfg.repo_dir) / "Dockerfile").is_file():
        return f"no Dockerfile in {cfg.repo_dir}"
    if cfg.expose in ("traefik", "proxy") and not valid_host(cfg.domain):
        return "domain is not a hostname"
    if password_problem(cfg.admin_pass):
        return "admin_pass: " + password_problem(cfg.admin_pass)
    if not re.fullmatch(r"[0-9a-f]{64}", cfg.file_key):
        return "file_key must be 64 hex characters"
    if not cfg.postgres_password:
        return "postgres_password is empty"
    if cfg.expose != "direct" and not cfg.trusted_cidrs:
        return "trusted_cidrs is required behind a proxy"
    return check_cidrs(cfg.trusted_cidrs)


# --- entry point -----------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(
        description=f"{APP} guided installer.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run with sudo: the install directory, the blob directory's "
               "ownership and the Docker socket all need it.")
    ap.add_argument("--answers", metavar="FILE",
                    help="pre-fill the wizard from a saved installer-answers.json")
    ap.add_argument("--non-interactive", action="store_true",
                    help="skip the wizard and apply --answers directly")
    ap.add_argument("--dry-run", action="store_true",
                    help="ask everything, then print the files instead of "
                         "writing them")
    ap.add_argument("--install-dir", metavar="DIR", help="override the default "
                    f"install directory ({DEFAULT_INSTALL_DIR})")
    args = ap.parse_args()

    global DRY_RUN
    DRY_RUN = args.dry_run

    if sys.version_info < (3, 8):
        print("This installer needs Python 3.8 or newer.", file=sys.stderr)
        return 1

    cfg = Config()
    cfg.repo_dir = str(Path(__file__).resolve().parent)
    cfg.postgres_password = gen_password()
    cfg.file_key = secrets.token_hex(32)

    if args.answers:
        try:
            cfg = Config.from_dict(json.loads(Path(args.answers).read_text()))
        except (OSError, ValueError) as exc:
            print(f"--answers: {exc}", file=sys.stderr)
            return 1
        if not cfg.repo_dir:
            cfg.repo_dir = str(Path(__file__).resolve().parent)
        if not cfg.postgres_password:
            cfg.postgres_password = gen_password()
        if not cfg.file_key:
            cfg.file_key = secrets.token_hex(32)
    if args.install_dir:
        cfg.install_dir = args.install_dir

    probe = probe_host(cfg.install_dir)

    if args.non_interactive:
        if not args.answers:
            print("--non-interactive needs --answers", file=sys.stderr)
            return 1
        normalize(cfg)
        problem = check_answers(cfg)
        if problem:
            print(f"answers: {problem}", file=sys.stderr)
            return 1
        if not probe.docker_ready and not args.dry_run:
            print("docker is not usable: " +
                  (probe.daemon_err or "not installed"), file=sys.stderr)
            return 1
        ok = run_plainly(cfg, probe, args.dry_run)
        if ok and not args.dry_run:
            if cfg.start_now:
                print(f"\n{APP} is at {cfg.base_url()} — sign in as "
                      f"{cfg.admin_user}.")
            else:
                print(f"\nConfiguration written to {cfg.install_dir}; nothing "
                      f"started.\nBring it up with: cd {cfg.install_dir} && "
                      f"docker compose -p {PROJECT} up -d --build")
        return 0 if ok else 1

    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("The wizard needs a terminal. For scripted installs use "
              "--non-interactive --answers FILE.", file=sys.stderr)
        return 1

    summary: list[str] = []
    ok = False

    def app(stdscr):
        nonlocal summary, ok, probe
        ui = Ui(stdscr)
        probe = wizard(ui, cfg, probe)
        plan = build_plan(cfg, probe, args.dry_run)
        runner = TaskRunner(ui, f"Installing {APP}", plan)
        ok = runner.run()
        runner.log("")
        runner.log("finished — press Enter" if ok else
                   "stopped at the failed step — press Enter")
        runner.wait_key()
        summary = final_screen(ui, cfg, ok, args.dry_run)

    try:
        curses.wrapper(app)
    except Aborted:
        print("Aborted. Nothing was changed unless a step above said otherwise.")
        return 130
    except curses.error as exc:
        print(f"curses failed: {exc}\nTry a larger terminal, or use "
              "--non-interactive --answers FILE.", file=sys.stderr)
        return 1

    # Repeat the outcome on stdout: the curses screen is gone, scrollback is not.
    for line in summary:
        print(line)
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
