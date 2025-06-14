# 📡 Wifi Scanner (Python)

A simple Python-based Wi-Fi scanner that lists nearby wireless networks and relevant details such as SSID, signal strength, and encryption type.

## 🔧 Features

- Cross-platform support (Windows/Linux/macOS*)
- Scans for available Wi-Fi networks
- Displays:
  - SSID (Network Name)
  - Signal Strength
  - Channel
  - Security Type
- Optional CSV/JSON export

> \*macOS support may be limited depending on available network tools

---

## 🚀 Usage

### 1. Clone the Repository

```bash
git clone https://github.com/k0shir0/Wifi-Scanner-Python.git
cd Wifi-Scanner-Python

2. Install Requirements

pip install -r requirements.txt

3. Run the Scanner

python wifi_scanner.py

If elevated permissions are required (Linux/macOS):

sudo python wifi_scanner.py


---

⚙️ Requirements

Python 3.7+

Packages used (in requirements.txt):

scapy

click (optional CLI support)

colorama (for colorful console output)

tabulate (formatted table output)



Install with:

pip install -r requirements.txt


---

🖥️ Example Output

+------------------+-----------------+---------+------------+
| SSID             | Signal Strength | Channel | Security   |
+------------------+-----------------+---------+------------+
| MyHomeNetwork    | -52 dBm         | 6       | WPA2       |
| GuestNetwork     | -72 dBm         | 11      | Open       |
+------------------+-----------------+---------+------------+


---

📁 Optional Arguments

You can customize the scan with optional flags:

python wifi_scanner.py --export json

Available options:

--export [csv/json] — Save results to file

--interface wlan0 — Specify a network interface (Linux)

--timeout 10 — Set scan duration in seconds



---

🛠️ Notes

On Linux, this tool may require sudo and access to a wireless interface in monitor mode.

On Windows, it uses netsh wlan show networks mode=bssid.

On macOS, consider using airport CLI tool or pywifi if available.



---

📦 TODO

[ ] macOS interface support

[ ] GUI frontend (Tkinter or PyQt)

[ ] Network filtering (by SSID or encryption)

[ ] Logging with timestamps



---

🧑‍💻 Author

github.com/k0shir0


---

📝 License

MIT License. See LICENSE for more details.

