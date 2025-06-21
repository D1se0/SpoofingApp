# SpoofingApp - Herramienta GUI para ARP y DNS Spoofing

![SpoofingApp Banner](https://user-images.githubusercontent.com/placeholder/banner.png)

---

## Descripción

**SpoofingApp** es una herramienta gráfica desarrollada en Python que permite realizar ataques de **ARP Spoofing** y **DNS Spoofing** sobre redes locales. Utiliza `scapy` para la manipulación de paquetes de red y `tkinter` para la interfaz gráfica, ofreciendo una experiencia visual moderna con un diseño cyberpunk/neón.

Esta aplicación está orientada a profesionales de la seguridad informática y pentesters que necesitan realizar pruebas de seguridad en redes LAN controladas.

---

## Características principales

- **ARP Spoofing bidireccional** para interceptar tráfico entre víctima y puerta de enlace.
- **DNS Spoofing selectivo**: redirige peticiones DNS de dominios específicos a la IP del atacante.
- **Escaneo de red ARP Broadcast** para descubrir hosts activos.
- **Funcionalidad para bloquear Internet a la víctima mediante ARP poisoning.**
- Interfaz gráfica elegante con fuentes personalizadas y colores estilo neón/cyberpunk.
- Registro en tiempo real de eventos y ataques en la interfaz.

---

## Requisitos

- **Sistema operativo:** Linux (probado en Kali Linux)
- **Python:** 3.7+
- **Dependencias de sistema:**
  - python3-tk
  - libpcap-dev
- **Dependencias Python:**
  - scapy

---

## Instalación

1. Clonar o descargar el repositorio con el script `SpoofingApp.py` y la fuente `PressStart2P-Regular.ttf`.

```bash
git clone https://github.com/D1se0/SpoofingApp.git
```

2. Ejecutar el script de instalación para preparar el entorno y dependencias:

```bash
chmod +x install_requirements.sh
sudo ./install_requirements.sh
```

> El script instala Python3, pip3, dependencias del sistema y Python, además copia la fuente personalizada para la interfaz.

3. Verificar que tienes permisos de root para ejecutar la herramienta (requisito para manipulación de red).

---

## Uso

Ejecutar el script con privilegios de root:

```bash
sudo python3 SpoofingApp.py
```

### Pasos para usar la herramienta:

  1. En el campo "IP de la víctima", ingresar la dirección IP del objetivo.
  2. En "Dominios a Spoofear", ingresar los dominios DNS separados por comas que deseas redirigir a tu máquina.
  3. Usar el botón "🌐 Escanear Red" para detectar hosts en la red local.
  4. Seleccionar un host en la tabla para autocompletar la IP víctima.
  5. Presionar "▶ Iniciar Spoofing" para comenzar el ataque ARP + DNS.
  5. Opcionalmente, usar "🛑 Dejar sin internet" para cortar la conexión de la víctima.
  6. Para detener ataques, usar "■ Detener".

---

## Advertencias y Consideraciones Legales

  - Esta herramienta es únicamente para uso en redes controladas y con consentimiento explícito.
  - Realizar ataques en redes sin autorización es ilegal y puede tener consecuencias graves.
  - El autor no se responsabiliza del mal uso de esta herramienta.

---

## Diseño y Estilo

  - Fuente personalizada Press Start 2P utilizada para interfaz retro/neón.
  - Colores estilo cyberpunk/neón: verde neón, rosa, cyan, naranja y morado.
  - Título animado y log visual con timestamps para mejor seguimiento.

---

## Estructura técnica

  - Uso intensivo de threading para mantener la UI responsiva y permitir operaciones concurrentes.
  - Sniffer de paquetes DNS con filtro BPF para detectar consultas desde la víctima.
  - Manipulación avanzada de paquetes ARP y DNS con scapy.
  - Gestión cuidadosa de hilos y sincronización de logs con threading.Lock.

---

## Contacto

Para dudas o sugerencias, contacta a:

  - Email: ciberseguridad12345@gmail.com
  - GitHub: D1se0

---

## Licencia

Este proyecto está bajo licencia MIT.

---

¡Gracias por usar SpoofingApp!
Mantén la ética y la seguridad primero.
