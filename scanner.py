import paramiko
import socket
import threading
from scapy.all import *

# Define a list to store successful FTP servers
successful_servers = []

# Function to perform the FTP login attempt
def ftp_login_attempt(host, port):
    try:
        # Create an SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect to the FTP server
        ssh.connect(host, port=port, username='anonymous')

        # Save the successful server to the list
        successful_servers.append((host, port))
        print(f"Successful login: {host}:{port}")

        # Close the SSH connection
        ssh.close()
    except Exception as e:
        # Handle any exceptions during the login attempt
        print(f"Error: {e}")

# Function to scan a single IP address
def scan_ip(ip):
    # Send a SYN packet to the IP address
    packet = IP(dst=ip)/TCP(dport=21, flags='S')
    send(packet, verbose=0)

    # Wait for the response
    response = sniff(count=1, filter='tcp and port 21', timeout=2)

    if response:
        # Extract the IP address from the response
        host = response[0][IP].src

        # Perform the FTP login attempt
        ftp_login_attempt(host, 21)

# Function to scan a range of IP addresses
def scan_range(start_ip, end_ip):
    # Calculate the number of threads needed
    num_threads = (end_ip - start_ip) // 255 + 1

    # Create and start the threads
    threads = []
    for i in range(num_threads):
        start = start_ip + i * 255
        end = min(start + 255, end_ip)
        thread = threading.Thread(target=scan_ip_range, args=(start, end))
        threads.append(thread)
        thread.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

# Function to scan a range of IP addresses
def scan_ip_range(start_ip, end_ip):
    for ip in range(start_ip, end_ip + 1):
        scan_ip(ip)

# Main function
def main():
    start_ip = '0.0.0.0'
    end_ip = '255.255.255.255'

    print("Scanning FTP servers...")
    scan_range(start_ip, end_ip)

    print("\nSuccessful FTP servers:")
    for server in successful_servers:
        print(server)

if __name__ == "__main__":
    main()
