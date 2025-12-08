## ✅ `README.md`

Custom Port Scanner (Python)

A lightweight yet powerful multi-threaded "port scanner" built in Python.  
It scans a target IP across a custom port range and performs "banner grabbing" on open ports — just like Nmap, but fully custom-built.

---

Features

- ✅ Custom target IP input
- ✅ Custom port range scanning (e.g., 20–80, 9999–10010)
- ✅ Multi-threaded for faster scanning
- ✅ "Banner grabbing" for open ports (e.g., SSH/HTTP service versions)
- ✅ Thread-safe console + file logging
- ✅ Clean `output.txt` with results from each run

---

Sample Output (Terminal)

```

Enter the IP address to scan: 127.0.0.1
Enter starting port number: 20
Enter ending port number: 80

\[+] port 22 OPEN (ssh) | Banner: SSH-2.0-OpenSSH\_8.4
\[-] port 23 NOT OPEN
\[+] port 80 OPEN (http) | Banner: HTTP/1.1 400 Bad Request

```

---

Log File: `output.txt`

```

Scan results for 127.0.0.1
Scan started at: 2025-07-07 05:45:45.852748

Port 22 OPEN (ssh)
Banner: SSH-2.0-OpenSSH\_8.4

Port 23 NOT OPEN
Port 80 OPEN (http)
Banner: HTTP/1.1 400 Bad Request

Scan ended at: 2025-07-07 05:45:46.854195

````

---

How to Run

Requirements:
- Python 3.11
- Works out of the box on Kali Linux, Ubuntu, or Windows (via terminal)

Run it:

python3 port_scanner.py


Input the IP and port range when prompted.

---

Why Banner Grabbing?

Banner grabbing is essential in:

* Penetration testing
* Service fingerprinting
* Vulnerability assessment

This scanner sends a basic `\r\n` to every open port and captures the response — helping identify what's running on that port (e.g., SSH, FTP, HTTP, Telnet).

---

Legal Usage

> This scanner is built for "educational and ethical hacking" purposes only.
> Never scan public IPs or networks without "explicit permission".

---

License

MIT License — free to use, modify, and share with credit.

---

Built With

* Python `socket`
* Python `threading`

---

@Royalian28
