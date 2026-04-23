import threading
import time
from scapy.all import AsyncSniffer, IP, TCP, Raw
from scapy.all import conf as scapy_conf


class Tracker:
    """Packet sniffer that ignores duplicate/retransmitted packets.
    Listens to server responses in a background thread and keeps track of
    unique packets. Retransmissions are ignored.
    """

    def __init__(self, interface, server_ip):
   
        self.interface = interface
        self.server_ip = server_ip
        self.lock = threading.Lock()
        self.seen_packets = {}
        self.latest_packet = {}
        self.sniffer = None

    def start(self):
        """Start listening for packets"""
        try:
            network_interface = scapy_conf.route.route(self.server_ip)[0]
        except Exception:
            network_interface = self.interface

        packet_filter = f"tcp and src host {self.server_ip}"

        self.sniffer = AsyncSniffer(
            iface=network_interface,
            filter=packet_filter,
            prn=self._handle_packet, 
            store=False  
        )
        self.sniffer.start()
        print(f"[tracker] Started listening on '{network_interface}' from server {self.server_ip}")

    def stop(self):
        """Stop listening for packets."""
        if self.sniffer and self.sniffer.running:
            self.sniffer.stop()
            print("[tracker] Stopped")


    def _handle_packet(self, packet):
        """Called automatically when a packet arrives. Process it and store if unique."""

        if IP not in packet or TCP not in packet:
            return

        tcp_layer = packet[TCP]
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport
        seq_num = tcp_layer.seq
        ack_num = tcp_layer.ack
        flags = str(tcp_layer.flags)

        # Check if this is a retransmitted packet
        if self._is_duplicate(src_port, dst_port, seq_num, ack_num, flags, packet):
            print(f"[tracker] Ignored retransmit: {flags} seq={seq_num} ack={ack_num}  {src_port}->{dst_port}")
            return

        # It's a new unique packet, record it
        with self.lock:
            flow = (src_port, dst_port)
            if flow not in self.seen_packets:
                self.seen_packets[flow] = set()
            self.seen_packets[flow].add((seq_num, ack_num, flags))

            # Save as the latest packet for this flow
            self.latest_packet[flow] = packet

    def _is_duplicate(self, src_port, dst_port, seq_num, ack_num, flags, packet):
        """Check if we've already seen this exact packet before."""
        
        with self.lock:
            flow = (src_port, dst_port)
            history = self.seen_packets.get(flow, set())

        retransmittable_flags = {"SA", "FA", "FPA", "S", "PA", "AP", "P", "F", "A"}
        flags_no_urgency = flags.replace("U", "")  # Ignore URG flag

        # CHECK 1: Have we seen this exact (seq, ack, flags) before?
        if (seq_num, ack_num, flags) in history:
            if flags_no_urgency in retransmittable_flags:
                return True  # This is a retransmit

        # CHECK 2: Data retransmit case
        # Server might send same data but with different ACK number
        if "P" in flags and "A" in flags:  
            payload = packet[Raw].load if Raw in packet else b""
            if len(payload) > 0: 
                for (prev_seq, _, prev_flags) in history:
                    if prev_seq == seq_num and "P" in prev_flags and "A" in prev_flags:
                        return True  

        return False  



    def get_latest_packet(self, src_port, dst_port):
        with self.lock:
            flow = (src_port, dst_port)
            return self.latest_packet.get(flow, None)

    def wait_for_packet(self, src_port, dst_port, timeout_seconds, check_interval=0.01):
        elapsed = 0.0
        while elapsed < timeout_seconds:
            pkt = self.get_latest_packet(src_port, dst_port)
            if pkt is not None:
                return pkt

            time.sleep(check_interval)
            elapsed += check_interval

        return None  # Timeout, no packet arrived

    def forget_flow(self, src_port, dst_port):
        """Forget all packets for this flow."""

        with self.lock:
            flow = (src_port, dst_port)
            self.latest_packet.pop(flow, None)
            self.seen_packets.pop(flow, None)

    def forget_all(self):
        """Forget all packets — calls at the start of each new test.
        Otherwise packets from the previous test might be treated as retransmits.
        """
        with self.lock:
            self.seen_packets.clear()
            self.latest_packet.clear()
