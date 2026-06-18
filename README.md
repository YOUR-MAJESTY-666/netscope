# NetScope

NetScope is a packet capture and network analysis tool. It runs in the background and gives you a web dashboard where you can see live network metrics like ping, jitter, and packet loss. It uses Scapy under the hood to grab packets directly from your network card.

## Features

* Web Interface: You can start and stop capturing packets straight from your browser without needing to use the command line.
* Live Stats: See real-time ping (RTT), jitter, and packet loss that updates every second.
* Traffic Breakdown: Shows a chart of protocols being used (TCP, UDP, ICMP, DNS).
* Top Talkers: See which IP addresses are using the most data.
* Security Alerts: Detects basic network anomalies like port scans and ICMP floods.
* Presets: Quick settings for monitoring games like CS:GO and Valorant.

## How to run it (Windows)

1. **Install requirements:**
Make sure you have Python installed. The project uses `uv` for dependency management.

2. **Start the tool:**
Just double-click the `start_hidden.vbs` file. It will ask for Administrator permissions because packet sniffing requires deep network access. Click "Yes". It will run silently in the background, so you won't see a terminal window.

3. **View the dashboard:**
Open your browser and go to `http://localhost:5000`. You can pick what you want to monitor and click "Start Capture".

## How to stop it

Since it runs silently in the background, closing your browser won't stop the server. To close it completely:
1. Open Task Manager (Ctrl + Shift + Esc).
2. Go to the Details tab.
3. Find `pythonw.exe`, right-click it, and click "End task".

## Architecture

* **Backend**: Runs a Flask server on port 5000.
* **Frontend**: HTML/JS dashboard that polls the backend every second for new data.
* **Sniffer**: A background Python thread using Scapy to capture packets and calculate stats.

## Security Rules

NetScope flags a few basic suspicious activities:
* Port Scan: Over 10 unique destination ports from the same IP in 5 seconds (High severity)
* High Packet Rate: More than 500 packets per second from one IP (High severity)
* ICMP Flood: More than 100 pings per second from one IP (High severity)
* Protocol Mismatch: e.g. finding non-TCP packets on port 80 (Medium severity)
* Large UDP: UDP packets with payloads larger than 1400 bytes (Low severity)
