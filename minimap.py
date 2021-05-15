# Minimap, a mini version of nmap

import argparse
import socket
import threading
import queue

PORT_STATUS_CLOSED = "Closed"
PORT_STATUS_CONNECTED = "Open"
PORT_STATUS_FIREWALL = "Firewalled"
PORT_STATUS_INVALID = "Invalid"
DEFAULT_TIMEOUT = "3"
DEFAULT_THREADS = "64"
DEFAULT_YAML = "1"                  # True
MAX_THREADS = 100

def main():
    # Parsing arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("Host", nargs="+", help="Hosts ...")
    parser.add_argument("-p", "--Ports", help="Ports, seperated by comma")
    parser.add_argument("-t", "--timeout", help="Time for timeout in seconds", type=int, default= DEFAULT_TIMEOUT)
    parser.add_argument("-n", "--threads", help="Number of threads to use", type=int, default= DEFAULT_THREADS)
    parser.add_argument("-y", "--yaml", help="Print results in YAML format", type=int, default= DEFAULT_YAML)
    args = parser.parse_args()
    print(args)

    # Assigning and fixing some arguments
    hosts = args.Host
    ports = parse_ports(args.Ports)
    timeout = args.timeout
    num_threads = args.threads
    num_host_threads = min(len(hosts), num_threads // 4 + 1)
    num_port_threads = max(1, num_threads - num_host_threads)
    yaml = args.yaml

    if (num_threads > MAX_THREADS):
        print("Number of threads cannot exceed maximim of " + MAX_THREADS)
        exit()

    # Initializing output dictionary
    port_statuses = {}
    for port in ports:
        port_statuses.update({port: PORT_STATUS_INVALID})

    host_queue = queue.Queue()
    for host in hosts:
        host_queue.put(host)

    host_threads = []

    for _ in range(num_host_threads):
        t = threading.Thread(target=host_thread_resolution, args=(host, ports, port_statuses, timeout, num_port_threads, host_queue))
        host_threads.append(t)
    for t in host_threads:
        t.start()
    for t in host_threads:
        t.join()

    print_results(hosts, port_statuses, yaml, args.Ports)

# Parse port argument and compile an array of ports to scan
def parse_ports(ports_arg):
    ports = ports_arg.split(",")
    for port in ports:
        if ("-" in str(port)):
            port_range = port.split("-")
            for new_port in range(int(port_range[0]), int(port_range[1]) + 1):
                ports.append(new_port)
            ports.remove(port)

    for i in range(len(ports)):
        ports[i] = int(ports[i])
    ports = list(set(ports))
    ports.sort()

    return ports

def host_thread_resolution(host, ports, port_statuses, timeout, num_port_threads, host_queue):
    while not host_queue.empty():
        host = host_queue.get()
        tcp_connect_scan(host, ports, port_statuses, timeout, num_port_threads)
    return

# Creates threads for all ports and calls tcp_connect_port for each
def tcp_connect_scan(host, ports, port_statuses, timeout, num_threads):
    port_threads = []

    jobs = queue.Queue()
    for port in ports:
        jobs.put(port)

    for _ in range(num_threads):
        t = threading.Thread(target=port_thread_resolution, args=(host, jobs, port_statuses, timeout))
        port_threads.append(t)
    for t in port_threads:
        t.start()
    for t in port_threads:
        t.join()

def port_thread_resolution(host, jobs, port_statuses, timeout):
    while not jobs.empty():
        port = jobs.get()
        tcp_connect_port(host, port, port_statuses, timeout)
    return

# Attempts to connect to the given host:port 
# Timed out at 2 seconds (In case of firewalls)
# Inserts the status code for the port into the dict parameter
# @param String host IP hostname
# @param int port Single port number
# @param dict port_statuses Dictionary with port as key and status as value 
def tcp_connect_port(host, port, port_statuses, timeout):
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientSocket.settimeout(timeout)

    try:
        clientSocket.connect((host, port))
        port_statuses.update({port: PORT_STATUS_CONNECTED})
    except socket.timeout:
        port_statuses.update({port: PORT_STATUS_FIREWALL})
    except ConnectionRefusedError:
        port_statuses.update({port: PORT_STATUS_CLOSED})
    finally:
        clientSocket.close()

# Print out the result of the scan
def print_results(hosts, port_statuses, yaml, port_list):
    if (yaml):
        print("%YAML 1.1")
        print("---")
        print("scanned: " + port_list)
        print("hosts:")
        for host in hosts:
            print("  - host: ", end = '')
            print(host)

            open_ports = []
            closed_ports = []
            firewalled_ports = [] 

            for port in port_statuses:
                if (port_statuses[port] == "Open"):
                    open_ports.append(port)
                elif(port_statuses[port] == "Closed"):
                    closed_ports.append(port)
                elif(port_statuses[port] == "Firewalled"):
                    firewalled_ports.append(port)
                else:
                    print("Invalid port found, aborting!")
                    exit()

            if (len(port_statuses) < 15):
                print("    open: ", end = '')
                print(open_ports)
                print("    closed: ", end = '')
                print(closed_ports)
                print("    firewalled: ", end = '')
                print(firewalled_ports)

            else:
                num_open = len(open_ports)
                num_closed = len(closed_ports)
                num_firewalled = len(firewalled_ports)

                if (num_open > num_firewalled and num_open > num_closed):
                    others = "Open"
                if (num_closed > num_firewalled and num_closed > num_open):
                    others = "Closed"
                if (num_firewalled > num_closed and num_firewalled > num_open):
                    others = "Firewalled"

                if not (others == "Open"):
                    print("    open: ", end = '')
                    print(open_ports)
                if not (others == "Closed"):
                    print("    closed: ", end = '')
                    print(closed_ports)
                if not (others == "Firewalled"):
                    print("    firewalled: ", end = '')
                    print(firewalled_ports)

                print("    others: ", end = '')
                print(others)

            print("")

    else:
        for host in hosts:
            print("Port statuses for host: " + host)
            for entry in port_statuses:
                print(str(entry) + ": " + port_statuses[entry])
            print("")