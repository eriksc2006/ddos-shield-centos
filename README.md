#  DDoS Protection Setup — CentOS Stream 10

Script de configuración automática de protección contra ataques DDoS para servidores **CentOS Stream 10**, desarrollado como parte del proyecto académico **"Técnicas avanzadas de protección contra ataques DDoS"** — Escuela de Ingenierías, Ciberseguridad, IUSH Medellín.

---

## ¿Qué hace este script?

Configura desde cero un servidor CentOS limpio con protección DDoS en múltiples capas y levanta dos servidores web con SSL. Todo automatizado en un solo archivo Python.

| Capa | Herramienta | Protección |
|------|------------|------------|
| Kernel | `sysctl` | SYN flood, IP spoofing, ICMP flood, fragmentación |
| Firewall | `nftables` | Blacklist dinámica, rate limiting por IP, bloqueo de paquetes inválidos |
| Detección | `Fail2Ban` | Baneo automático por SSH, Apache, Nginx y HTTP flood |
| Recursos | `ulimits` / `systemd` | Prevención de resource exhaustion |
| Web | `Apache` + `Nginx` | Servidores con SSL/TLS y páginas de prueba |
| Monitoreo | Script bash | Monitor en tiempo real de conexiones e IPs bloqueadas |

---

## Requisitos

- CentOS Stream 10 (limpia o con instalación mínima)
- Acceso root o sudo
- Conexión a internet (para instalar paquetes)
- Python 3 (viene preinstalado en CentOS Stream 10)

---

## Instalación y uso

```bash
# 1. Clonar el repositorio
git clone https://github.com/eriksc2006/ddos-shield-centos.git
cd ddos-shield-centos

# 2. Dar permisos de ejecucion
chmod +x ddos_setup.py

# 3. Ejecutar como root
sudo ./ddos_setup.py
```

Al finalizar el script mostrará las URLs de los servidores web activos y un resumen de todos los comandos de gestión.

---

## Servidores web que levanta

| Servidor | HTTP | HTTPS |
|----------|------|-------|
| Apache | `http://IP` | `https://IP` |
| Nginx | `http://IP:8080` | `https://IP:8443` |

> El certificado SSL es autofirmado. El navegador pedirá aceptar una excepción de seguridad la primera vez.

---

## Gestionar IPs bloqueadas

### nftables

```bash
# Ver IPs en la blacklist
sudo nft list set inet filter blacklist

# Eliminar una IP especifica
sudo nft delete element inet filter blacklist { 192.168.1.X }

# Vaciar toda la blacklist
sudo nft flush set inet filter blacklist
```

### Fail2Ban

```bash
# Ver todas las jails activas
sudo fail2ban-client status

# Ver IPs baneadas en SSH
sudo fail2ban-client status sshd

# Desbanear una IP especifica
sudo fail2ban-client set sshd unbanip 192.168.1.X

# Desbanear todas las IPs
sudo fail2ban-client unban --all
```

---

## Monitoreo en tiempo real

```bash
watch -n 5 /usr/local/bin/ddos-monitor.sh
```

Muestra: conexiones activas por estado, top 10 IPs con más conexiones, IPs en blacklist, bans activos de Fail2Ban y estado de los servidores web.

---

## Estructura del repositorio

```
ddos-protection-centos/
├── ddos_setup.py        # Script principal
└── README.md            # Este archivo
```

---

## Lo que configura en detalle

### 1. Parámetros de kernel (`/etc/sysctl.d/99-ddos-protection.conf`)
- SYN cookies activadas para resistir SYN floods
- Filtrado de ruta inversa para bloquear IP spoofing
- Límite de respuestas ICMP para prevenir floods
- Deshabilitado IP forwarding, source routing y ICMP redirects

### 2. Firewall nftables (`/etc/nftables.conf`)
- Blacklist dinámica con expiración automática de 1 hora
- Rate limiting: máx. 50 conexiones SYN/seg por IP
- Rate limiting: máx. 30 req/seg en puertos 80, 443, 8080 y 8443
- SSH limitado a 3 intentos por minuto
- UDP limitado a 100 paquetes/seg
- firewalld desactivado y enmascarado

### 3. Fail2Ban (`/etc/fail2ban/jail.local`)
- SSH: ban de 2 horas tras 3 intentos fallidos
- Apache/Nginx auth: ban tras 5 fallos
- HTTP flood: ban de 1 hora si supera 100 req en 60 segundos

### 4. Límites de recursos
- Máximo 65536 archivos abiertos por proceso
- Máximo 8192 procesos por usuario
- Límites aplicados a nivel de kernel via systemd

### 5. Apache + SSL
- `mod_ssl` y `mod_headers` instalados
- Certificado autofirmado RSA 2048 bits
- Headers de seguridad: HSTS, X-Frame-Options, X-Content-Type-Options
- Solo TLSv1.2 y TLSv1.3 habilitados

### 6. Nginx + SSL
- Rate limiting nativo: 30 req/seg, máx. 20 conexiones simultáneas por IP
- Certificado SSL compartido con Apache
- Headers de seguridad incluidos

---

## Autor

**Erik A. Soto Castaño**

Escuela de Ingenierías — Ingenieria de Sistemas
Institución Universitaria Salazar y Herrera — IUSH Medellín

---

## Licencia

MIT License — libre para usar, modificar y distribuir con atribución.
