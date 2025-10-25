
#!/usr/bin/env python3
"""
Network Packet Analyzer for macOS
"""
import socket
import scapy.all as scapy
from scapy.layers import http
import argparse
import time
import sys
from colorama import Fore, Style, init
from collections import defaultdict
init()
class MacOSPacketAnalyzer:
    def __init__(self, interface=None, protocol_filter=None):
        self.interface = interface or self.detect_default_interface()
        self.protocol_filter = protocol_filter
        self.packet_count = 0
        self.start_time = time.time()
        self.syn_count = defaultdict(int)
        self.my_ips = self.get_my_ips()
    def get_my_ips(self):
        """Get all IP addresses of this computer"""
        my_ips = []
        try:
            # Get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            my_ips.append(s.getsockname()[0])
            s.close()
        except:
            pass
        return my_ips
    def detect_default_interface(self):
        try:
            interfaces = scapy.get_if_list()
            for preferred in ['en0', 'en1', 'eth0']:
                if preferred in interfaces:
                    return preferred
            return interfaces[0] if interfaces else 'en0'
        except Exception as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
            return 'en0'
    def detect_port_scan(self, packet):
        """Improved port scan detection - ignores own computer"""
        if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.IP):
            if packet[scapy.TCP].flags == 'S':  # SYN packet
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst

                # IGNORE if the source is our own computer (outgoing connections)
                if src_ip in self.my_ips:
                    return  # ← This is the key fix!

                # IGNORE if destination is our own computer (incoming to us)
                if dst_ip in self.my_ips:
                    self.syn_count[src_ip] += 1

                    # Only alert for incoming connection attempts TO our computer
                    if self.syn_count[src_ip] == 5:
                        print(
                            f"{Fore.RED}🚨 WARNING: Suspicious incoming connections from {src_ip}{Style.RESET_ALL}")
                    elif self.syn_count[src_ip] > 10:
                        print(f"{Fore.RED}🚨 SECURITY ALERT: Possible port scan from {src_ip}{Style.RESET_ALL}")
    def print_security_status(self):
        """Improved security summary - focuses on real threats"""
        print(f"\n{Fore.CYAN}🔒 SECURITY SUMMARY:{Style.RESET_ALL}")

        # Only count incoming connection attempts (real threats)
        incoming_threats = {ip: count for ip, count in self.syn_count.items() if ip not in self.my_ips}

        if not incoming_threats:
            print(f"{Fore.GREEN}✅ No incoming threats detected{Style.RESET_ALL}")
            print(f"{Fore.GREEN}   Your computer appears secure{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}⚠️  Incoming connection attempts:{Style.RESET_ALL}")
            for ip, count in incoming_threats.items():
                if count >= 10:
                    level = f"{Fore.RED}HIGH - Port scan detected{Style.RESET_ALL}"
                elif count >= 5:
                    level = f"{Fore.YELLOW}MEDIUM - Suspicious activity{Style.RESET_ALL}"
                else:
                    level = f"{Fore.BLUE}LOW - Monitoring{Style.RESET_ALL}"
                print(f"   {ip}: {count} attempts - {level}")
    def process_packet(self, packet):
        self.packet_count += 1
        current_time = time.time() - self.start_time
        self.detect_port_scan(packet)

        print(f"\n{Fore.CYAN}📦 Packet #{self.packet_count} (+{current_time:.2f}s){Style.RESET_ALL}")
        
        # IP Layer
        if packet.haslayer(scapy.IP):
            ip = packet[scapy.IP]
            print(f"{Fore.GREEN}🌐 IP:{Style.RESET_ALL} {ip.src} → {ip.dst}")
            print(f"   Protocol: {ip.proto}, TTL: {ip.ttl}")
        
        # TCP Layer
        if packet.haslayer(scapy.TCP):
            tcp = packet[scapy.TCP]
            print(f"{Fore.BLUE}📨 TCP:{Style.RESET_ALL} {tcp.sport} → {tcp.dport}")
            print(f"   Flags: {tcp.flags}")
        
        # UDP Layer
        if packet.haslayer(scapy.UDP):
            udp = packet[scapy.UDP]
            print(f"{Fore.MAGENTA}📬 UDP:{Style.RESET_ALL} {udp.sport} → {udp.dport}")
        
        # HTTP Layer
        if packet.haslayer(http.HTTPRequest):
            http_req = packet[http.HTTPRequest]
            print(f"{Fore.RED}🌍 HTTP Request:{Style.RESET_ALL}")
            host = http_req.Host.decode() if http_req.Host else "N/A"
            path = http_req.Path.decode() if http_req.Path else "N/A"
            print(f"   Host: {host}, Path: {path}")
        # DNS Layer - Detect website names  ← ADD THIS NEW SECTION
        if packet.haslayer(scapy.DNS):
            dns = packet[scapy.DNS]
            print(f"{Fore.YELLOW}📡 DNS Query:{Style.RESET_ALL}")
            if dns.qd:  # Query section
                query = dns.qd.qname.decode() if dns.qd.qname else "N/A"
                print(f"   Website: {query}")
        # Payload
        if packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load
            print(f"{Fore.WHITE}📝 Payload ({len(payload)} bytes):{Style.RESET_ALL}")
            try:
                text = payload.decode('utf-8', errors='ignore')
                if any(c.isprintable() for c in text[:20]):
                    print(f"   Preview: {text[:100]}")
            except:
                print("   [Binary data]")
    def start_capture(self, count=0):
        print(f"{Fore.GREEN}🚀 Starting packet capture on {self.interface}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Press Ctrl+C to stop...{Style.RESET_ALL}")

        try:
            scapy.sniff(
                iface=self.interface,
                prn=self.process_packet,
                store=False,
                count=count,
                filter=self.protocol_filter
            )
        except KeyboardInterrupt:
            print(f"\n{Fore.GREEN}✅ Capture stopped by user{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}❌ Capture error: {e}{Style.RESET_ALL}")
            return

        # ALWAYS show summary - whether stopped by user or completed normally
        print(f"{Fore.GREEN}📊 Total packets captured: {self.packet_count}{Style.RESET_ALL}")
        self.print_security_status()
def main():
    parser = argparse.ArgumentParser(description="Network Packet Analyzer")
    parser.add_argument("-i", "--interface", help="Network interface")
    parser.add_argument("-f", "--filter", help="BPF filter (tcp, udp, port 80)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Packet count")
    
    args = parser.parse_args()
    
    analyzer = MacOSPacketAnalyzer(
        interface=args.interface,
        protocol_filter=args.filter
    )
    analyzer.start_capture(count=args.count)

if __name__ == "__main__":
    main()
