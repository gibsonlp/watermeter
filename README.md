# MV-MA (NT) Wireless Water Meter Analyzer

This repository contains a complete toolset for analyzing MV-MA (NT) wireless water meter traffic. It captures raw packets, decodes proprietary meter data, and stores it in a database for analysis, alerting, and visualization.

## 📂 Repository Contents

* **`water_analyzer/`**: Core Python package containing the logic, ingester and web monitor
* **`config/`**: Configuration templates.
* **`db/`**: Database schema and setup scripts.
* **`systemd/`**: Service files for running the tool as a background daemon.
* **`reverse-tool/`**: Original scripts used to reverse-engineer the protocol.
* **`OpenWRT/`**: Configuration files for an OpenWRT based sniffer device, can really run on anything but you'd need to modify it

## 📏 Units of Measurement
The meter reports values in the following units:
* **Volume:** Dekaliters (DAL)
    * `1 DAL` = `10 Liters`
    * Example: `101.11 m³` (CBM) = `10,111 DAL`
* **Flow:** Centiliters per minute (cL/min)
    * `100 cL/min` = `1 L/min`
    * Example: `101.11 L/min` = `10,111 cL/min`

---

## 🚀 Installation
DISCLAIMER: The installation steps were never tested, feel free to suggeset fixes.

### 1. Prepare the System
Install the required system dependencies (assuming Debian/Ubuntu):
```bash
sudo apt update
sudo apt install python3-pip mariadb-server libpcap-dev

```

### 2. Setup the Application

Copy the application code to the standard location:

```bash
sudo cp -r water_analyzer /opt/
sudo chown -R $USER:$USER /opt/water_analyzer

```

### 3. Install Python Dependencies

Install the required Python libraries:

```bash
cd /opt/water_analyzer
pip3 install -r requirements.txt

```

### 4. Configure the Database
Create the database and user using the provided schema:

```bash
sudo mysql -p DBNAME < db/schema.sql

```

### 5. Configuration
Copy the example configuration and edit it with your specific details (Database credentials, Meter Serial Number, etc.):

```bash
sudo mkdir -p /etc/water_analyzer
sudo cp config/water_analyzer.conf.example /etc/water_analyzer/water_analyzer.conf
sudo nano /etc/water_analyzer/water_analyzer.conf

```

---

## ⚙️ Service Setup (Systemd)

### 1. Deploy Service Files

Copy the service definitions to the system directory:

```bash
sudo cp systemd/*.service /etc/systemd/system/
sudo cp systemd/*.timer /etc/systemd/system/

```

### 2. Configure User Permissions

Edit the service files to run as your specific user (replace `User=pi` with your username):

```bash
sudo nano /etc/systemd/system/water-ingester.service
sudo nano /etc/systemd/system/water-reporter-hourly.service
sudo nano /etc/systemd/system/water-reporter-daily.service
sudo nano /etc/systemd/system/water-ulanzi.service

```

### 3. Enable and Start

Reload the daemon to recognize new files, then enable the timers and services:

```bash
sudo systemctl daemon-reload

# 1. Start the Packet Ingester (The listener)
sudo systemctl enable --now water-ingester.service

# 2. Start the Reporters (The logic engine)
# Note: Enable the TIMERS, not the services directly!
sudo systemctl enable --now water-reporter-hourly.timer
sudo systemctl enable --now water-reporter-daily.timer

# 3. (Optional) Start Ulanzi Smart Clock Service
sudo systemctl enable --now water-ulanzi.service

```

---

## 🛠 Advanced / Optional

### OpenWRT Configuration

If you prefer to run the sniffer on an OpenWRT router, the following files are provided for customization:

| File | Description |
| --- | --- |
| `OpenWRT/files/etc/dropbear/authorized_keys` | Add your SSH key for passwordless access. |
| `OpenWRT/files/etc/rc.local` | Startup script modifications. |
| `OpenWRT/files/etc/config/network` | Custom network settings (Static IP, etc.). |
| `OpenWRT/config` | Build configuration (menuconfig) for custom builds. |

### Reverse Engineering

* **`reverse-tool/packetmaker.py`**: A script used to simulate packets during the reverse engineering phase. Useful for debugging or protocol research.

```

```
