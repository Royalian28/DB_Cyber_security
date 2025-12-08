import socket
from datetime import datetime
import threading

# Create thread lock globally
lock = threading.Lock()

# Target IP input
target = input("Enter the IP address to scan: ")

# Custom port range input
try:
    start_port = int(input("Enter starting port number: "))
    end_port = int(input("Enter ending port number: "))
except ValueError:
    print("Invalid port input. Please enter numeric values.")
    exit()

print(f"\n scanning {target} address from port{start_port} to {end_port}.....")
print("started at.", datetime.now().strftime("%Y-%m-%d--%H-%M-%S"))
print("- - - - - - - - - - - - - - - - - - - - -  - - - - - --  - - - - - - - - - - - -  - - - - - - - - - - - - -")

# Add scan header at the top of each scan session
with open("output.txt", "a") as output:
    output.write(f"\nScan results for {target}\n")
    output.write(f"Scan started at: {datetime.now()}\n")

def scan_port(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((target, port))
        with lock:
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "UNKNOWN"

                banner = ""
                try:
                    s.sendall(b"\r\n")
                    banner = s.recv(1024).decode().strip()
                except:
                    banner = "No banner or not readable"

                print(f"[+] port {port} OPEN ({service}) | Banner: {banner}")
                with open("output.txt", "a") as output:
                    output.write(f"Port {port} OPEN ({service})\n")
                    output.write(f"Banner: {banner}\n\n")
            else:
                print(f"[-] port {port} NOT OPEN")
                with open("output.txt", "a") as output:
                    output.write(f"Port {port} NOT OPEN\n")
        s.close()
    except Exception as e:
        with lock:
            print(f"Error on port:{port} : {e}")

# Launch threads
threads = []
for port in range(start_port, end_port + 1):
    t = threading.Thread(target=scan_port, args=(port,))
    threads.append(t)
    t.start()

for t in threads:
    t.join()

with open("output.txt", "a") as output:
    output.write(f"Scan ended at: {datetime.now()}\n")

print("\n✅ Scan complete and banner info saved to 'output.txt'")

