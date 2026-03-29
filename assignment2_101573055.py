"""
Author: Bruck Dessalegn
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import datetime
import os
import platform
import socket
import sqlite3
import threading

print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {os.name}")

# Maps well-known TCP port numbers to their typical service names for display.
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt",
}


class NetworkTool:
    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # Using @property lets code read target like a normal attribute while the real
    # value stays private in __target, which hides implementation details. The setter
    # centralizes validation so every assignment runs the same empty-string check
    # instead of trusting callers to validate. Together they keep the interface
    # simple and enforce rules in one place instead of scattered checks.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
            return
        self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner subclasses NetworkTool, so it does not redefine target storage or
# access. Its constructor calls super().__init__(target), which runs NetworkTool's
# __init__ and sets the private __target field. Methods like scan_port then use
# self.target, which relies on NetworkTool's property getter to read that value.
class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        # Q4: What would happen without try-except here?
        # Without try-except, a failed connect on an unreachable host can raise
        # OSError/socket errors and stop the worker thread, so one bad port could
        # abort that thread's execution. The scan would be less reliable and the
        # program might print an ugly traceback instead of a short, controlled message.
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                status = "Open"
            else:
                status = "Closed"
            service_name = common_ports.get(port, "Unknown")
            with self.lock:
                self.scan_results.append((port, status, service_name))
        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def get_open_ports(self):
        return [r for r in self.scan_results if r[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # Threading overlaps many TCP connection attempts so total wall-clock time is
    # closer to one timeout than to thousands of sequential timeouts. Scanning 1024
    # ports one after another could take many minutes if each waits up to a second,
    # whereas parallel scans finish much faster while respecting the same per-port timeout.
    def scan_range(self, start_port, end_port):
        threads = []
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()


def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                port INTEGER,
                status TEXT,
                service TEXT,
                scan_date TEXT
            )"""
        )
        for port, status, service in results:
            scan_date = str(datetime.datetime.now())
            cursor.execute(
                "INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                (target, port, status, service, scan_date),
            )
        conn.commit()
        conn.close()
    except sqlite3.Error:
        pass


def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()
        conn.close()
        if not rows:
            print("No past scans found.")
            return
        for row in rows:
            _rid, tgt, port, status, service, scan_date = row
            print(f"[{scan_date}] {tgt} : Port {port} ({service}) - {status}")
    except sqlite3.Error:
        print("No past scans found.")


# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":
    target_ip = input("Enter target IP address (press Enter for 127.0.0.1): ").strip()
    if target_ip == "":
        target_ip = "127.0.0.1"

    try:
        start_port = int(input("Enter starting port number (1-1024): "))
        end_port = int(input("Enter ending port number (1-1024): "))
    except ValueError:
        print("Invalid input. Please enter a valid integer.")
    else:
        if not (1 <= start_port <= 1024) or not (1 <= end_port <= 1024):
            print("Port must be between 1 and 1024.")
        elif end_port < start_port:
            print("End port must be greater than or equal to start port.")
        else:
            scanner = PortScanner(target_ip)
            print(f"Scanning {target_ip} from port {start_port} to {end_port}...")
            scanner.scan_range(start_port, end_port)
            open_ports = scanner.get_open_ports()
            print(f"--- Scan Results for {target_ip} ---")
            for port, status, service in open_ports:
                print(f"Port {port}: {status} ({service})")
            print("------")
            print(f"Total open ports found: {len(open_ports)}")
            save_results(target_ip, scanner.scan_results)
            hist = input("Would you like to see past scan history? (yes/no): ").strip().lower()
            if hist == "yes":
                load_past_scans()


# Q5: New Feature Proposal
# I would add a "Service Family Grouper" that reads open ports from get_open_ports and,
# for each tuple, uses nested if / elif / else to map the port number into a functional
# family (Web, Mail, Remote access, Database, or Other). A list comprehension would then
# turn those labeled rows into concise lines for a grouped text report or CSV export.
# Diagram: See diagram_101573055.png in the repository root
