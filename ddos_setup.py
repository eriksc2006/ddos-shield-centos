#!/usr/bin/env python3
"""
==============================================================
  SCRIPT DE PROTECCION DDoS + SERVIDOR WEB PARA CENTOS STREAM 10
  Configura desde cero: Apache, Nginx, SSL y proteccion DDoS
  Ejecutar como root: sudo python3 ddos_setup.py
==============================================================
"""

import os
import sys
import subprocess
import shutil
import socket

# ─────────────────────────────────────────────
# COLORES
# ─────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ok(msg):   print(f"  {GREEN}[OK]{RESET} {msg}")
def warn(msg): print(f"  {YELLOW}[AVISO]{RESET} {msg}")
def err(msg):  print(f"  {RED}[ERROR]{RESET} {msg}")
def step(msg): print(f"\n{BOLD}{CYAN}{msg}{RESET}")
def info(msg): print(f"  {msg}")

# ─────────────────────────────────────────────
# UTILIDADES
# ─────────────────────────────────────────────
def run(cmd, check=True, capture=False):
    try:
        result = subprocess.run(
            cmd, shell=True, check=check,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            text=True
        )
        return result
    except subprocess.CalledProcessError as e:
        return e

def write_file(path, content):
    dirpath = os.path.dirname(path)
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)
    with open(path, "w") as f:
        f.write(content)

def cmd_exists(cmd):
    return shutil.which(cmd) is not None

def get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def check_root():
    if os.geteuid() != 0:
        err("Este script debe ejecutarse como root.")
        err("Usa: sudo python3 ddos_setup.py")
        sys.exit(1)

def check_centos():
    try:
        with open("/etc/os-release") as f:
            content = f.read()
        if "centos" not in content.lower() and "rhel" not in content.lower():
            warn("Este script esta optimizado para CentOS/RHEL.")
    except FileNotFoundError:
        warn("No se pudo verificar la distribucion del SO.")

# ─────────────────────────────────────────────
# 1. SYSCTL
# ─────────────────────────────────────────────
SYSCTL_CONTENT = """# Proteccion DDoS - Parametros de kernel
# Generado por ddos_setup.py

net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 3
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_ratelimit = 100
net.ipv4.icmp_ratemask = 88089
net.ipv4.icmp_echo_ignore_all = 0
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_tw_reuse = 1
net.core.somaxconn = 1024
net.core.netdev_max_backlog = 5000
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.udp_mem = 65536 131072 262144
net.ipv4.ipfrag_high_thresh = 262144
net.ipv4.ipfrag_low_thresh = 196608
net.ipv4.ipfrag_time = 15
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
"""

def configurar_sysctl():
    step("[1/8] Parametros de kernel (sysctl)")
    write_file("/etc/sysctl.d/99-ddos-protection.conf", SYSCTL_CONTENT)
    result = run("sysctl -p /etc/sysctl.d/99-ddos-protection.conf", check=False, capture=True)
    if result.returncode == 0:
        ok("Parametros de kernel aplicados.")
    else:
        warn("Algunos parametros se aplicaran al reiniciar.")

# ─────────────────────────────────────────────
# 2. NFTABLES
# ─────────────────────────────────────────────
NFTABLES_CONTENT = """#!/usr/sbin/nft -f
flush ruleset

table inet filter {

    set blacklist {
        type ipv4_addr
        flags dynamic, timeout
        timeout 1h
    }

    chain input {
        type filter hook input priority 0; policy drop;

        iifname "lo" accept
        ct state established,related accept
        ct state invalid drop
        ip saddr @blacklist drop

        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept

        tcp dport 22 ct state new limit rate over 3/minute burst 5 packets drop
        tcp dport 22 accept

        tcp dport { 80, 443, 8080, 8443 } ct state new limit rate over 30/second burst 60 packets accept

        tcp flags syn ct state new limit rate over 50/second burst 100 packets accept

        ip protocol udp limit rate over 100/second burst 200 packets accept
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy accept;
        ip protocol udp limit rate over 500/second burst 1000 packets accept
    }
}
"""

def configurar_nftables():
    step("[2/8] Firewall con nftables")
    if cmd_exists("firewall-cmd"):
        run("systemctl stop firewalld",    check=False)
        run("systemctl disable firewalld", check=False)
        run("systemctl mask firewalld",    check=False)
        ok("firewalld detenido y enmascarado.")

    if not cmd_exists("nft"):
        run("dnf install -y nftables", check=False)

    write_file("/etc/nftables.conf", NFTABLES_CONTENT)
    result = run("nft -f /etc/nftables.conf", check=False, capture=True)
    if result.returncode == 0:
        ok("Reglas nftables aplicadas.")
    else:
        err(f"Error: {result.stderr}")
        return

    run("systemctl enable nftables", check=False)
    run("systemctl restart nftables", check=False)
    ok("nftables habilitado y activo.")

# ─────────────────────────────────────────────
# 3. FAIL2BAN
# ─────────────────────────────────────────────
FAIL2BAN_JAIL = """[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5
backend  = systemd

[sshd]
enabled  = true
port     = ssh
maxretry = 3
bantime  = 7200

[apache-auth]
enabled  = true
port     = http,https
logpath  = /var/log/httpd/error_log
maxretry = 5

[nginx-http-auth]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/error.log
maxretry = 5

[http-flood]
enabled  = true
port     = http,https
filter   = http-flood
logpath  = /var/log/nginx/access.log
           /var/log/httpd/access_log
maxretry = 100
findtime = 60
bantime  = 3600
"""

def configurar_fail2ban():
    step("[3/8] Fail2Ban")
    if not cmd_exists("fail2ban-client"):
        run("dnf install -y epel-release", check=False)
        result = run("dnf install -y fail2ban", check=False)
        if result.returncode != 0:
            warn("No se pudo instalar fail2ban.")
            return

    write_file("/etc/fail2ban/jail.local", FAIL2BAN_JAIL)
    run("systemctl enable fail2ban", check=False)
    result = run("systemctl restart fail2ban", check=False)
    if result.returncode == 0:
        ok("Fail2Ban configurado y activo.")
    else:
        warn("Fail2Ban instalado. Verifica: systemctl status fail2ban")

# ─────────────────────────────────────────────
# 4. LIMITES DE RECURSOS
# ─────────────────────────────────────────────
SYSTEMD_LIMITS = """[Manager]
DefaultLimitNOFILE=65536
DefaultLimitNPROC=8192
DefaultTasksMax=4096
"""

def configurar_limites():
    step("[4/8] Limites de recursos del sistema")
    with open("/etc/security/limits.conf", "r") as f:
        existing = f.read()
    if "ddos_setup.py" not in existing:
        with open("/etc/security/limits.conf", "a") as f:
            f.write("\n# --- Agregado por ddos_setup.py ---\n")
            f.write("* soft nofile 65536\n* hard nofile 65536\n")
            f.write("* soft nproc  4096\n* hard nproc  8192\n")
            f.write("* soft stack  8192\n* hard stack  16384\n")
        ok("Limites de ulimit configurados.")
    else:
        ok("Limites de ulimit ya estaban configurados.")

    os.makedirs("/etc/systemd/system.conf.d", exist_ok=True)
    write_file("/etc/systemd/system.conf.d/ddos-limits.conf", SYSTEMD_LIMITS)
    run("systemctl daemon-reexec", check=False)
    ok("Limites de systemd configurados.")

# ─────────────────────────────────────────────
# 5. APACHE + SSL
# ─────────────────────────────────────────────
def get_apache_page(ip):
    return """<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Apache - Servidor Protegido</title>
  <style>
    *{{margin:0;padding:0;box-sizing:border-box}}
    body{{font-family:'Segoe UI',sans-serif;background:#0D1117;color:#E2E8F0;
         display:flex;justify-content:center;align-items:center;min-height:100vh}}
    .card{{background:#162032;border:1px solid #1A56DB;border-radius:12px;
           padding:48px;max-width:600px;text-align:center}}
    .badge{{display:inline-block;background:#1A56DB;color:white;border-radius:20px;
            padding:4px 16px;font-size:13px;margin-bottom:24px}}
    h1{{color:#22D3EE;font-size:2rem;margin-bottom:12px}}
    p{{color:#94A3B8;line-height:1.6;margin-bottom:8px}}
    .tags{{margin-top:32px;display:flex;gap:12px;justify-content:center;flex-wrap:wrap}}
    .tag{{background:#0E1F3D;border:1px solid #22D3EE;color:#22D3EE;
          border-radius:8px;padding:8px 20px;font-size:14px}}
    .ip{{margin-top:24px;color:#64748B;font-size:13px}}
  </style>
</head>
<body>
  <div class="card">
    <span class="badge">Apache HTTP Server</span>
    <h1>Servidor Web Activo</h1>
    <p>Protegido contra ataques DDoS con nftables y Fail2Ban.</p>
    <div class="tags">
      <span class="tag">nftables</span>
      <span class="tag">Fail2Ban</span>
      <span class="tag">SSL/TLS</span>
      <span class="tag">sysctl hardening</span>
    </div>
    <p class="ip">IP: """ + ip + """ &nbsp;|&nbsp; Puerto: 80 / 443</p>
  </div>
</body>
</html>"""

def get_apache_ssl_conf(ip):
    return """<VirtualHost *:443>
    ServerName """ + ip + """
    DocumentRoot /var/www/html
    SSLEngine on
    SSLCertificateFile    /etc/ssl/ddos-certs/server.crt
    SSLCertificateKeyFile /etc/ssl/ddos-certs/server.key
    SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite HIGH:!aNULL:!MD5:!RC4
    SSLHonorCipherOrder on
    Header always set Strict-Transport-Security "max-age=63072000"
    Header always set X-Frame-Options DENY
    Header always set X-Content-Type-Options nosniff
    ErrorLog  /var/log/httpd/ssl_error_log
    CustomLog /var/log/httpd/ssl_access_log combined
</VirtualHost>

<VirtualHost *:80>
    ServerName """ + ip + """
    DocumentRoot /var/www/html
    ErrorLog  /var/log/httpd/error_log
    CustomLog /var/log/httpd/access_log combined
</VirtualHost>
"""

def configurar_apache(ip):
    step("[5/8] Apache (httpd) + SSL")
    result = run("dnf install -y httpd mod_ssl mod_headers", check=False)
    if result.returncode != 0:
        err("No se pudo instalar Apache.")
        return

    write_file("/var/www/html/index.html", get_apache_page(ip))
    ok("Pagina de prueba de Apache creada.")

    os.makedirs("/etc/ssl/ddos-certs", exist_ok=True)
    run(
        'openssl req -x509 -nodes -days 365 -newkey rsa:2048 '
        '-keyout /etc/ssl/ddos-certs/server.key '
        '-out /etc/ssl/ddos-certs/server.crt '
        '-subj "/C=CO/ST=Antioquia/L=Medellin/O=IUSH/CN=' + ip + '"',
        check=False
    )
    ok("Certificado SSL autofirmado generado.")

    write_file("/etc/httpd/conf.d/ssl-ddos.conf", get_apache_ssl_conf(ip))
    run("systemctl enable httpd", check=False)
    result = run("systemctl restart httpd", check=False)
    if result.returncode == 0:
        ok(f"Apache activo en http://{ip} y https://{ip}")
    else:
        warn("Apache instalado. Verifica: systemctl status httpd")

# ─────────────────────────────────────────────
# 6. NGINX + SSL
# ─────────────────────────────────────────────
def get_nginx_page(ip):
    return """<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Nginx - Servidor Protegido</title>
  <style>
    *{{margin:0;padding:0;box-sizing:border-box}}
    body{{font-family:'Segoe UI',sans-serif;background:#0D1117;color:#E2E8F0;
         display:flex;justify-content:center;align-items:center;min-height:100vh}}
    .card{{background:#162032;border:1px solid #22D3EE;border-radius:12px;
           padding:48px;max-width:600px;text-align:center}}
    .badge{{display:inline-block;background:#22D3EE;color:#0D1117;border-radius:20px;
            padding:4px 16px;font-size:13px;font-weight:bold;margin-bottom:24px}}
    h1{{color:#22D3EE;font-size:2rem;margin-bottom:12px}}
    p{{color:#94A3B8;line-height:1.6;margin-bottom:8px}}
    .tags{{margin-top:32px;display:flex;gap:12px;justify-content:center;flex-wrap:wrap}}
    .tag{{background:#0E1F3D;border:1px solid #1A56DB;color:#1A56DB;
          border-radius:8px;padding:8px 20px;font-size:14px}}
    .ip{{margin-top:24px;color:#64748B;font-size:13px}}
  </style>
</head>
<body>
  <div class="card">
    <span class="badge">Nginx</span>
    <h1>Servidor Web Activo</h1>
    <p>Protegido contra ataques DDoS con rate limiting y Fail2Ban.</p>
    <div class="tags">
      <span class="tag">nftables</span>
      <span class="tag">Fail2Ban</span>
      <span class="tag">Rate Limit</span>
      <span class="tag">SSL/TLS</span>
    </div>
    <p class="ip">IP: """ + ip + """ &nbsp;|&nbsp; Puerto: 8080 / 8443</p>
  </div>
</body>
</html>"""

def get_nginx_conf(ip):
    return """limit_conn_zone $binary_remote_addr zone=conn_limit:10m;
limit_req_zone  $binary_remote_addr zone=req_limit:10m rate=30r/s;

server {
    listen 8080;
    server_name """ + ip + """;
    root /var/www/nginx;
    index index.html;
    limit_conn conn_limit 20;
    limit_req  zone=req_limit burst=50 nodelay;
    location / { try_files $uri $uri/ =404; }
    error_log  /var/log/nginx/error.log;
    access_log /var/log/nginx/access.log;
}

server {
    listen 8443 ssl;
    server_name """ + ip + """;
    root /var/www/nginx;
    index index.html;
    ssl_certificate     /etc/ssl/ddos-certs/server.crt;
    ssl_certificate_key /etc/ssl/ddos-certs/server.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    limit_conn conn_limit 20;
    limit_req  zone=req_limit burst=50 nodelay;
    location / { try_files $uri $uri/ =404; }
}
"""

def configurar_nginx(ip):
    step("[6/8] Nginx + SSL")
    result = run("dnf install -y nginx", check=False)
    if result.returncode != 0:
        err("No se pudo instalar Nginx.")
        return

    os.makedirs("/var/www/nginx", exist_ok=True)
    write_file("/var/www/nginx/index.html", get_nginx_page(ip))
    ok("Pagina de prueba de Nginx creada.")

    write_file("/etc/nginx/conf.d/ddos-site.conf", get_nginx_conf(ip))
    ok("Configuracion SSL de Nginx aplicada.")

    run("systemctl enable nginx", check=False)
    result = run("systemctl restart nginx", check=False)
    if result.returncode == 0:
        ok(f"Nginx activo en http://{ip}:8080 y https://{ip}:8443")
    else:
        warn("Nginx instalado. Verifica: systemctl status nginx")

# ─────────────────────────────────────────────
# 7. MONITOR
# ─────────────────────────────────────────────
MONITOR_SCRIPT = """#!/bin/bash
echo "============================================"
echo "  MONITOR DDoS - $(date)"
echo "============================================"
echo ""
echo "=== CONEXIONES ACTIVAS POR ESTADO ==="
ss -s
echo ""
echo "=== TOP 10 IPs CON MAS CONEXIONES ==="
ss -tn | awk 'NR>1{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -10
echo ""
echo "=== IPs EN BLACKLIST NFTABLES ==="
nft list set inet filter blacklist 2>/dev/null || echo "nftables no disponible"
echo ""
echo "=== FAIL2BAN - BANS ACTIVOS ==="
fail2ban-client status 2>/dev/null || echo "fail2ban no disponible"
echo ""
echo "=== ESTADO SERVIDORES WEB ==="
systemctl is-active httpd && echo "Apache: ACTIVO" || echo "Apache: INACTIVO"
systemctl is-active nginx && echo "Nginx:  ACTIVO" || echo "Nginx:  INACTIVO"
echo ""
echo "=== CARGA DEL SISTEMA ==="
uptime
"""

def instalar_monitor():
    step("[7/8] Script de monitoreo")
    path = "/usr/local/bin/ddos-monitor.sh"
    write_file(path, MONITOR_SCRIPT)
    os.chmod(path, 0o755)
    ok(f"Monitor instalado en {path}")

# ─────────────────────────────────────────────
# 8. SERVICIOS INNECESARIOS
# ─────────────────────────────────────────────
def deshabilitar_servicios():
    step("[8/8] Desactivar servicios innecesarios")
    for svc in ["bluetooth","avahi-daemon","cups","postfix","rpcbind","nfs-server"]:
        result = run(f"systemctl is-enabled {svc}", check=False, capture=True)
        if result.returncode == 0 and "enabled" in result.stdout:
            run(f"systemctl disable --now {svc}", check=False)
            ok(f"Desactivado: {svc}")
        else:
            info(f"Ya inactivo o no instalado: {svc}")

# ─────────────────────────────────────────────
# HERRAMIENTAS
# ─────────────────────────────────────────────
def instalar_herramientas():
    step("[+] Instalando herramientas de diagnostico")
    for tool in ["tcpdump", "net-tools"]:
        if not cmd_exists(tool):
            result = run(f"dnf install -y {tool}", check=False, capture=True)
            ok(f"Instalado: {tool}") if result.returncode == 0 else warn(f"No se pudo instalar: {tool}")
        else:
            ok(f"Ya instalado: {tool}")

# ─────────────────────────────────────────────
# RESUMEN
# ─────────────────────────────────────────────
def mostrar_resumen(ip):
    print(f"""
{BOLD}{CYAN}
======================================================
  CONFIGURACION COMPLETADA EXITOSAMENTE
======================================================{RESET}

{BOLD}Servidores web activos:{RESET}
  Apache  ->  http://{ip}         https://{ip}
  Nginx   ->  http://{ip}:8080    https://{ip}:8443
  (SSL autofirmado: acepta la excepcion en el navegador)

{BOLD}Gestionar IPs bloqueadas:{RESET}

  Ver blacklist nftables:
    {CYAN}sudo nft list set inet filter blacklist{RESET}

  Eliminar una IP de nftables:
    {CYAN}sudo nft delete element inet filter blacklist {{ 192.168.1.X }}{RESET}

  Vaciar toda la blacklist:
    {CYAN}sudo nft flush set inet filter blacklist{RESET}

  Ver IPs baneadas por Fail2Ban:
    {CYAN}sudo fail2ban-client status sshd{RESET}

  Desbanear IP en Fail2Ban:
    {CYAN}sudo fail2ban-client set sshd unbanip 192.168.1.X{RESET}

  Desbanear todas:
    {CYAN}sudo fail2ban-client unban --all{RESET}

{BOLD}Monitoreo en tiempo real:{RESET}
    {CYAN}watch -n 5 /usr/local/bin/ddos-monitor.sh{RESET}

{YELLOW}Reinicia la VM para aplicar todos los cambios:{RESET}
    {CYAN}sudo reboot{RESET}

======================================================
""")

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    print(f"""
{BOLD}{CYAN}
======================================================
  SETUP DDoS + APACHE + NGINX - CENTOS STREAM 10
  ddos_setup.py
======================================================{RESET}
""")
    check_root()
    check_centos()

    ip = get_ip()
    info(f"IP detectada: {CYAN}{ip}{RESET}")

    configurar_sysctl()
    configurar_nftables()
    configurar_fail2ban()
    configurar_limites()
    configurar_apache(ip)
    configurar_nginx(ip)
    instalar_monitor()
    deshabilitar_servicios()
    instalar_herramientas()
    mostrar_resumen(ip)

if __name__ == "__main__":
    main()
