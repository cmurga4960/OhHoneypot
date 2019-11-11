# OhHoneypot
Android ready ohhoney python honeypot.  This honeypot is designed to fool Nmap by utalizing it's own database and spcifications.  Utalizes tcpdump and iptables to run on top of any services and traffic.  
<br />
<br />
# Instalation
cd OhHoneypot/OhHoneyPy/
./install.sh
<br />
# Usage
For help and options: <br />
	```python3 ohhoney.py -h``` <br />
Typical usage: <br />
	```ptyhon3 ohhoney.py -i eth0 -o "Camera" -s "80,tcp,http;4960,udp,domain"``` <br />
