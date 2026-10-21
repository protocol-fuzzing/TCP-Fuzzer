from scapy.all import send, sniff, conf, IP, TCP, Raw
from response import Timeout, ConcreteResponse
import re
import time
import os 
from collections import deque


class Sender:
    """This class contains functions for creating and sending TCP packets. It communicates with the learner via the learnerSocket class"""

    def __init__(self, serverMAC=None, serverIP="191.168.10.1", serverPort = 7991,
             networkInterface="lo", networkInterfaceType=0, senderPort=15000, senderPortMinimum=1025,
             senderPortMaximum=65535, portCooldown=3600,
             isVerbose=0, waitTime=0.1, resetWait=0.1, resetMechanism=0, dpiAlertsFile=None, dpiWaitTime=0.05,): # increased default waitTime of server to 0.1 to capture multiple responses (sr)
        # data on sender and server needed to send packets
        self.serverIP = serverIP
        self.serverPort = serverPort
        self.serverMAC = serverMAC
        self.networkInterface = networkInterface
        self.senderPort = senderPort
        self.senderPortMinimum = senderPortMinimum
        self.senderPortMaximum = senderPortMaximum
        if not 1 <= self.senderPortMinimum <= self.senderPortMaximum <= 65535:
            raise ValueError("Invalid Tcp source-port range")

        # seconds a used source port must stay idle before it may be reused
        self.portCooldown = portCooldown
        self._fresh_ports = iter(
            port for port in range(self.senderPortMinimum, self.senderPortMaximum + 1)
            if port != self.senderPort
        )
        # (port, time it was last used), oldest first
        self._retired_ports = deque()

        # time to wait for a response from the server before concluding a timeout
        self.waitTime = waitTime

        # time to pause after the reset RST, before the next query starts
        self.resetWait = resetWait

        # TODO: need to remove this, the client should decide on the reset mechanism.
        self.resetMechanism = resetMechanism

        #set verbosity (0/1)
        self.isVerbose = isVerbose

        # track the last seq/ack received from the server, used during reset to send a valid RST
        self.lastRecvSeq = 0
        self.lastRecvAck = 0
        

        # Tracks seen packets (by seq/ack/flags) across all sr() calls within one test,
        # cleared on reset so duplicates/retransmissions within a test are filtered out.
        self.response_history = set()

        # Composite label when one input produces multiple responses.
        # Example: "PA_ACK2_D1|FA_ACK2"
        self.response_flag_sequence = None

        # DPI monitoring 
        self.dpiAlertsFile = dpiAlertsFile
        self.dpiWaitTime = dpiWaitTime
        self.last_dpi_rule = None

        if self.dpiAlertsFile is not None:
            self.checkDpiConfiguration()

       


    def __str__(self):
        return "Sender with parameters: " + str(self.__dict__)

    def refreshNetworkPort(self):
        """Use a fresh source port; after all are used, reuse the oldest once its cool-down has passed."""
        if self.senderPortMinimum <= self.senderPort <= self.senderPortMaximum:
            self._retired_ports.append((self.senderPort, time.monotonic()))

        next_port = next(self._fresh_ports, None)
        if next_port is None:
            if not self._retired_ports:
                raise RuntimeError("No sender ports available.")
            next_port, last_used = self._retired_ports.popleft()
            wait = last_used + self.portCooldown - time.monotonic()
            if wait > 0:
                print(f"*** All ports used; waiting {wait:.0f} s for port {next_port} to cool down ***")
                time.sleep(wait)
            print(f"*** Reusing port {next_port} ***")

        print(f"previous local port: {self.senderPort}")
        self.setSenderPort(next_port)
        print(f"next local port: {self.senderPort}\n")
        return self.senderPort

    def sendPacket(self,flagsSet, seqNr, ackNr):
        """Creates a packet and sends it over the network using scapy, the response is also gathered using scapy"""
        packet = self.createPacket(flagsSet, seqNr, ackNr, '')
        response = self.sendAndRecv(packet)
        return response

    def setServerPort(self, newPort):
        self.serverPort = newPort

    def setSenderPort(self, newPort):
        self.senderPort = newPort
 
    # function that creates packet from data strings/integers
    def createPacket(self, tcpFlagsSet, seqNr, ackNr, payload, destIP = None, destPort = None, srcPort = None, ipFlagsSet="DF"):
        """Creates a packet from the given arguments"""

        # TODO couldn't this be done using default values in the function header?
        if destIP is None:
            destIP = self.serverIP
        if destPort is None:
            destPort = self.serverPort
        if srcPort is None:
            srcPort = self.senderPort


        pIP = IP(dst=destIP, flags=ipFlagsSet, version=4)
        pTCP = TCP(sport=srcPort,
        dport=destPort,
        seq=seqNr,
        ack=ackNr,
        flags=tcpFlagsSet)

        # Either we have a payload or we don't.
        if payload:
            p = pIP / pTCP / Raw(load=payload)
        else:
            p = pIP / pTCP        
        return p

    def captureResponses(self, packet, waitTime):
        """Send packet and return every segment of its flow that arrives within waitTime."""
      
        # A hostname destination (e.g. "localhost" in CI) is stored by scapy as a Net
        # object, which conf.route.route() cannot handle; str() gives its address.
        dst = str(packet[IP].dst)
        iface = conf.route.route(dst)[0]
        bpf = (f"tcp and src host {dst} and src port {packet[TCP].dport} "
               f"and dst host {packet[IP].src} and dst port {packet[TCP].sport}")
        # Open the socket before sending, so that no early reply is missed.
        # unlike sniff()'s default listen socket, an L2socket skips outgoing
        # packets, so a reply is not seen twice on the loopback interface.
        sock = conf.L2socket(iface=iface, filter=bpf)
        try:
            send(packet, verbose=self.isVerbose)
            return list(sniff(opened_socket=sock, timeout=waitTime))
        finally:
            sock.close()

    def sendAndRecv(self, packet, waitTime = None):
        """Sends a packet and retrieves a response"""

        if waitTime is None:
            waitTime = self.waitTime

        # Never reuse a response sequence from previous packet.
        self.response_flag_sequence = None

        # Never reuse a match from the previous packet.
        self.last_dpi_rule = None

        if packet is not None:
            self.clientIP = packet[IP].src
            # Remember where the Snort log ends before sending.
            dpi_marker = self.getDpiMarker()
            
            # Capture every segment of the flow, not only one reply:
            # e.g. the Ubuntu server in response to FA, sometimes sends
            # two separate packets, one with 'A' flag and one with 'FA' flag,
            # instead of one packet with 'FA' flag.
            responses = self.captureResponses(packet, waitTime)

            # Deduplicate retransmissions across all captures within this test.
            # self.response_history is cleared on reset, so it spans exactly one test.
            unique_responses = []
           
            for resp in responses:
                key = (resp['TCP'].seq, resp['TCP'].ack, int(resp['TCP'].flags))
                # Ubuntu in synchronized states, upon receiving unexpected packetes (e.g. 'S' when in Established),
                # responds with empty acknowledgment segement ('A') containing the current same sequenece number and 
                # acknowledgment number and stays in the same state.
                # we need to distinguish retransmissions from these empty acknowledgments that might be sent multiple times
                # in response to multiple unexpected packets (They all have the same seq/ack/flags hence the same key in the history set).
                if key in self.response_history and self.intToFlags(int(resp['TCP'].flags)) != 'A':
                    print('*** Retransmitted packet, ignoring duplicate: ' + str(resp['TCP'].flags) + " " + str(resp.seq) + " " + str(resp.ack) + ' ***')
                else:
                    self.response_history.add(key)
                    unique_responses.append(resp)
            responses = unique_responses
            # time.sleep(1.0)

            if self.checkForDpiAlert(dpi_marker, packet):
                self.last_dpi_rule = "RuleMatched"

                print("*** DPI detected the packet payload: " + self.last_dpi_rule + " ***")

            if len(responses) == 0:
                return Timeout()
            elif len(responses) == 1:
                response = responses[0] 
                self.response_flag_sequence = self.build_ack_response_label(packet, response)
                return response
            else:  # len(responses) > 1: multiple replies
                for response in responses:
                    flag_str = self.intToFlags(int(response[TCP].flags))
                    seq_ack_str = f"{flag_str} {response[TCP].seq} {response[TCP].ack}"
                    if response.haslayer(Raw):
                        payload_bytes = bytes(response[Raw].load)
                        if payload_bytes:
                            seq_ack_str += f", payload={payload_bytes.decode('utf-8', errors='replace')}"
                    print(f"*** Response: {seq_ack_str} ***")

                # First merge consecutive responses that describe the same
                # TCP sequence position. For example, A followed by FA with
                # identical seq/ack values becomes one FA response.
                response_groups = []
                for response in responses:
                    response_key = (
                        int(response[TCP].seq),
                        int(response[TCP].ack),
                    )

                    if response_groups and response_groups[-1][0] == response_key:
                        response_groups[-1][1].append(response)
                    else:
                        response_groups.append((response_key, [response]))

                normalized_responses = []
                for _, response_group in response_groups:
                    if len(response_group) == 1:
                        normalized_responses.append(response_group[0])
                    else:
                        normalized_responses.append(
                            self.merge_responses(response_group)
                        )

                consecutive_responses = [normalized_responses[0]]

                for response in normalized_responses[1:]:
                    previous = consecutive_responses[-1]

                    previous_flags = int(previous[TCP].flags)

                    consumed = (
                        len(bytes(previous[Raw].load))
                        if previous.haslayer(Raw)
                        else 0
                    )

                    if previous_flags & 0x02:  # SYN
                        consumed += 1

                    if previous_flags & 0x01:  # FIN
                        consumed += 1

                    expected_seq = (
                        int(previous[TCP].seq) + consumed
                    ) & 0xFFFFFFFF

                    if int(response[TCP].seq) == expected_seq:
                        consecutive_responses.append(response)
                    else:
                        print(
                            "*** Ignoring non-consecutive response: "
                            f"{self.intToFlags(int(response[TCP].flags))} "
                            f"seq={response[TCP].seq}, "
                            f"expected={expected_seq} ***"
                        )

                normalized_responses = consecutive_responses

                # Responses at different sequence positions remain separate
                # ordered outputs, represented with the | separator.
                response_labels = []
                for response in normalized_responses:
                    response_labels.append(self.build_ack_response_label(packet, response))

                self.response_flag_sequence = "|".join(response_labels)

                # Preserve seq, ack, and payload from the final normalized
                # response for the learner's TCP context.
                last_response = normalized_responses[-1]

                print(
                    f"*** Final responses: "
                    f"{self.response_flag_sequence}; "
                    f"using final seq={last_response[TCP].seq}, "
                    f"ack={last_response[TCP].ack} ***"
                )

                return last_response

    # Merges multiple responses into one Scapy packet by OR-ing all TCP flags.
    # All responses must share the same seq and ack numbers (checked by the caller).
    def merge_responses(self, responses): 
        merged_flags = 0
        pktFlags = [] 
        for pkt in responses:
            pktFlags.append(pkt['TCP'].flags)
            merged_flags |= int(pkt['TCP'].flags)
        merged = responses[0].copy()
            
        # Use the packet with a payload as the base, so the payload is preserved in the merge.
        responses_with_payload = [pkt for pkt in responses if pkt.haslayer(Raw)]
        if len(responses_with_payload) > 1:
            pass  # TODO: multiple responses have a payload — figure out which one to use.
        elif len(responses_with_payload) == 1:
            merged = responses_with_payload[0].copy()

        merged['TCP'].flags = merged_flags
        flag_strs = ', '.join(self.intToFlags(int(f)) for f in pktFlags)
        merged_str = self.intToFlags(merged_flags)
        print(f'*** Merging responses:  {flag_strs} -> {merged_str} ***')
        return merged

    def checkDpiConfiguration(self):
        """Check that the Snort alert file can be read."""
        if not os.path.isfile(self.dpiAlertsFile):
            raise RuntimeError(f"DPI is enabled, but the Snort alert file: {self.dpiAlertsFile} does not exist.")
        try:
            with open(self.dpiAlertsFile, 'r'):
                pass
        except PermissionError:
            raise RuntimeError(f"DPI is enabled, but the Snort alert file: {self.dpiAlertsFile} cannot be read. Check permissions.")

    def getDpiMarker(self):
        """
        Return the current size of the alert file.

        New alerts written after this position belong to the packet
        we are about to send.
        """

        if self.dpiAlertsFile is None:
            return None
        try:
            return os.path.getsize(self.dpiAlertsFile)
        except OSError as error:
            raise RuntimeError(f"Failed to get size of DPI alert file: {self.dpiAlertsFile}. Error: {error}")

    def checkForDpiAlert(self, marker, packet):
        """
        Check for a Snort alert belonging to the TCP flow of packet.
        """
        if self.dpiAlertsFile is None or marker is None:
            return False

        expected_source_port = int(packet[TCP].sport)
        expected_dest_ip = str(packet[IP].dst)
        expected_dest_port = int(packet[TCP].dport)

        endpoint_pattern = re.compile(
            rf'\{{TCP\}}\s+\S+:{expected_source_port}\s+->\s+'
            rf'{re.escape(expected_dest_ip)}:'
            rf'{expected_dest_port}(?:\s|$)'
        )

        deadline = time.monotonic() + self.dpiWaitTime

        while True:
            try:
                current_size = os.path.getsize(self.dpiAlertsFile)
                if current_size < marker:
                    marker = 0

                with open(self.dpiAlertsFile, 'r', encoding='utf-8', errors="replace") as alert_file:
                    alert_file.seek(marker)
                    new_alerts = alert_file.read()

            except OSError as error:
                raise RuntimeError(f"Failed to read DPI alert file: {self.dpiAlertsFile}. Error: {error}")

            for line in new_alerts.splitlines():
                dpi_alert = "Mapper send Data" in line 
                correct_connection = endpoint_pattern.search(line) 
                if dpi_alert and correct_connection:
                    return True

            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                return False

            time.sleep(min(0.01, remaining_time))  # Sleep for a short interval before checking again

    # FIXME possibly refactor response.py a bit, the names are confusing
    def scapyResponseParse(self, scapyResponse):
        """Extracts the relevant TCP data from the scapy response"""

        flags = scapyResponse[TCP].flags
        seq = scapyResponse[TCP].seq
        ack = scapyResponse[TCP].ack
        concreteResponse = ConcreteResponse(self.intToFlags(flags), seq, ack)
        return concreteResponse


    def checkForFlag(self, x, flagPosition):
        """Checks if the TCP flag at the given position is set"""

        # Check if the bit is set
        if x & 2 ** flagPosition == 0:
            return False
        else:
            return True

    def intToFlags(self, x):
        """Convert TCP flags from int to string

        The flags-parameter of a network packets is returned as an int, this function converts
        it to a string (such as "FA" if the Fin-flag and Ack-flag have been set)
        """

        result = ""
        if self.checkForFlag(x, 0):
            result = result + "F"
        if self.checkForFlag(x, 1):
            result = result + "S"
        if self.checkForFlag(x, 2):
            result = result + "R"
        if self.checkForFlag(x, 3):
            result = result + "P"
        if self.checkForFlag(x, 4):
            result = result + "A"
        if self.checkForFlag(x, 5):
            result = result + "U"
        return result

    def build_ack_response_label(self, sent_packet, response):
        """
         'ACK1' means the server acknowledged either the flag (S or F) or the payload of length 1.
         'ACK2' means the server acknowledged both the flag and the payload of length 1.
         'D1' means the server sent a payload of length 1, echoing the payload sent by the client.
        """
        server_response_flags = int(response[TCP].flags)
        response_label = self.intToFlags(server_response_flags) # like: A S SA ...
        sent_packet_flags = int(sent_packet[TCP].flags)
        sent_payload_length = len(bytes(sent_packet[TCP].payload))
        sent_sequence_length = sent_payload_length

        if sent_packet_flags & 0x02: # SYN
            sent_sequence_length += 1
        if sent_packet_flags & 0x01: # FIN
            sent_sequence_length += 1

        # pure ACK packets consume no sequence space and RST packets are not acknowledged.
        if(sent_sequence_length> 0 
           and (sent_packet_flags & 0x04) == 0 # sent packet was not RST
           and (server_response_flags & 0x10) != 0 # responce has ACK)
        ):
            sent_sequence_number = int(sent_packet[TCP].seq)
            server_ack_number = int(response[TCP].ack)
         
            # the calculation also handles 32-bit TCP sequence wraparound.
            ack_advance = (server_ack_number - sent_sequence_number) & 0xFFFFFFFF

            if 0 < ack_advance < 0x80000000:
                acknowledged_length = min (ack_advance, sent_sequence_length)
                response_label += f"_ACK{acknowledged_length}"
    

        if response.haslayer(Raw):
            response_payload_length = len(bytes(response[Raw].load))
            if response_payload_length > 0:
                response_label += f"_D{response_payload_length}"

        return response_label


    def isFlags(self, inputString):
        """Checks if a given string is a valid TCP flag"""

        isFlags = False
        matchResult = re.match("[FSRPAU]*", inputString)
        if matchResult is not None:
            isFlags = matchResult.group(0) == inputString
        return isFlags

    # TODO When is this needed?
    def captureResponse(self, waitTime=None):
        if waitTime is None:
            waitTime = self.waitTime
        return self.sendInput("nil", None, None, None, waitTime)

    # sends input over the network to the server
    def sendInput(self, flags, seqNr, ackNr, payload, waitTime=None):
        if waitTime is None:
            waitTime = self.waitTime

        timeBefore = time.time()

        if flags != "nil":
            packet = self.createPacket(flags, seqNr, ackNr, payload)
        else:
            packet = None
        response = self.sendAndRecv(packet, waitTime)

        # wait a certain amount of time after sending the packet
        timeAfter = time.time()
        timeSpent = timeAfter - timeBefore
        if timeSpent < waitTime:
            time.sleep(waitTime - timeSpent)
        if type(response) is not Timeout:
            self.lastRecvSeq = response[TCP].seq
            self.lastRecvAck = response[TCP].ack
        return response

    def sendRawReset(self, seq):
        """Send the RST that closes the server's connection after a query.
        Its answer is never used, so there is no capture and no DPI poll; only a
        short pause (resetWait) before the next query starts.
        """
        send(self.createPacket("R", seq, 0, ''), verbose=self.isVerbose)
        time.sleep(self.resetWait)

    # resets by way of a valid reset. Requires a valid sequence number. Avoids problems encountered with the maximum
    # number of connections allowed on a port.
    def sendValidReset(self,seq):
        if self.resetMechanism == 0 or self.resetMechanism == 2:
            self.sendInput("R", seq, 0, '')
        if self.resetMechanism == 1 or self.resetMechanism == 2:
            self.sendReset()

    # resets the connection by changing the port number. Be careful, on some OSes (Win 8) upon hitting a certain number of
    # connections opened on a port, packets are sent to close down connections, which affects learning. TCP configurations
    # can be altered, but I'd say in case learning involves many queries, use the other method.
    def sendReset(self):
        self.response_history.clear() # new test starts, forget seen packets.
        # forget the old connection, so the next reset RST never uses its numbers.
        self.lastRecvSeq = 0
        self.lastRecvAck = 0
        self.refreshNetworkPort()


    def shutdown(self):
        pass
