#!/bin/bash

if [[ $EUID -ne 0 ]]; then
  echo "Este script debe ejecutarse como root."
  exit 1
fi

set -e

echo "Actualizando lista de paquetes..."
sudo apt-get update -y || { echo "Error actualizando paquetes"; exit 1; }

# Función para verificar si un paquete está instalado
is_installed() {
    dpkg -s "$1" &> /dev/null
}

echo "Instalando python3 y pip3 si no están instalados..."

if is_installed python3 && is_installed python3-pip; then
    echo "python3 y pip3 ya están instalados, omitiendo..."
else
    sudo apt-get install -y python3 python3-pip || {
        echo "Error instalando python3 o pip3"
        echo "Intentando corregir dependencias rotas con apt --fix-broken install..."
        sudo apt-get install -f -y || { echo "No se pudo corregir dependencias"; exit 1; }
        sudo apt-get install -y python3 python3-pip || { echo "Error instalando python3 o pip3 después de corregir dependencias"; exit 1; }
    }
fi

echo "Instalando dependencias del sistema para scapy y tkinter..."

PKGS=("python3-tk" "libpcap-dev")

for pkg in "${PKGS[@]}"; do
    if is_installed "$pkg"; then
        echo "$pkg ya está instalado, omitiendo..."
    else
        sudo apt-get install -y "$pkg" || {
            echo "Error instalando $pkg"
            echo "Intentando corregir dependencias rotas con apt --fix-broken install..."
            sudo apt-get install -f -y || { echo "No se pudo corregir dependencias"; exit 1; }
            sudo apt-get install -y "$pkg" || { echo "Error instalando $pkg después de corregir dependencias"; exit 1; }
        }
    fi
done

echo "Instalando paquetes Python requeridos..."

pip3 install --upgrade pip --break-system-packages || { echo "Error actualizando pip"; exit 1; }

if python3 -c "import scapy" &> /dev/null; then
    echo "scapy ya está instalado, omitiendo..."
else
    pip3 install scapy --break-system-packages || { echo "Error instalando scapy"; exit 1; }
fi

echo "Instalando fuente Press Start 2P desde directorio local..."

FONTS_DIR="$HOME/.fonts"
FONT_FILE="PressStart2P-Regular.ttf"

mkdir -p "$FONTS_DIR"

if [ -f "$FONT_FILE" ]; then
  cp -f "$FONT_FILE" "$FONTS_DIR/" || { echo "Error copiando la fuente"; exit 1; }
  fc-cache -f -v || { echo "Error actualizando caché de fuentes"; exit 1; }
  echo "Fuente instalada correctamente en $FONTS_DIR."
else
  echo "No se encontró el archivo $FONT_FILE en el directorio actual."
  exit 1
fi

echo "¡Todo listo! Puedes ejecutar tu script Python."
