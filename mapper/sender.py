from scapy.all import sr, sr1, IP, TCP, Raw
from response import Timeout, ConcreteResponse
import re
import time
import random
import os 

# variables used to retain last sequence/acknowledgment sent
seqVar = 0
ackVar = 0


class Sender:
    """This class contains functions for creating and sending TCP packets. It communicates with the learner via the learnerSocket class"""

    def __init__(self, serverMAC=None, serverIP="191.168.10.1", serverPort = 7991,
             networkInterface="lo", networkInterfaceType=0, senderPort=15000, senderPortMinimum=20000,
             senderPortMaximum=40000, portNumberFile = "sn.txt",
             isVerbose=0, waitTime=0.1, resetMechanism=0, dpiAlertsFile=None, dpiWaitTime=0.05,): # increased default waitTime of server to 0.1 to capture multiple responses (sr)
        # data on sender and server needed to send packets
        self.serverIP = serverIP
        self.serverPort = serverPort
        self.serverMAC = serverMAC
        self.networkInterface = networkInterface
        self.senderPort = senderPort
        self.senderPortMinimum = senderPortMinimum
        self.senderPortMaximum = senderPortMaximum
        self.portNumberFile = portNumberFile

        # time to wait for a response from the server before concluding a timeout
        self.waitTime = waitTime


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
        # Example: "PA_DATA_1|FA"
        self.response_flag_sequence = None

        # DPI monitoring 
        self.dpiAlertsFile = dpiAlertsFile
        self.dpiWaitTime = dpiWaitTime
        self.last_dpi_rule = None

        if self.dpiAlertsFile is not None:
            self.checkDpiConfiguration()

       


    def __str__(self):
        return "Sender with parameters: " + str(self.__dict__)

    # TODO the functions pertaining to refreshing ports seem a bit odd, they read from a file. Couldn't they just increment the number instead?
    # TODO I have changed this to select a port randomly, that could backfire if im unlucky enough to select a port which was very recently
    # used, causing nondeterminism. I haven't run into problems yet though.
    def refreshNetworkPort(self):
        """Chooses a new port to send packets to"""
        print("previous local port: " + str(self.senderPort))
        #self.setSenderPort(self.getNextPort())
        self.setSenderPort(random.randint(self.senderPortMinimum, self.senderPortMaximum))
        print("next local port: " + str(self.senderPort)+"\n")
        return self.senderPort

    # TODO the functions pertaining to refreshing ports seem a bit odd, they read from a file. Couldn't they just increment the number instead?
    def getNextPort(self):
        f = open(self.portNumberFile,"a+")
        f.seek(0)
        line = f.readline()
        if line == '' or int(line) < self.senderPortMinimum:
            networkPort = self.senderPortMinimum
        else:
            senderPortRange = self.senderPortMaximum - self.senderPortMinimum
            if senderPortRange == 0:
                networkPort = self.senderPortMinimum
            else:
                networkPort = self.senderPortMinimum + (int(line) + 1) % senderPortRange
        f.close()
        f = open(self.portNumberFile, "w")
        f.write(str(networkPort))
        f.close()
        return networkPort

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
            
            # Used sr instead of sr1 to capture multiple responses 
            # e.g. the Ubuntu server in response to FA, sometimes sends 
            # two separate packets, one with 'A' flag and one with 'FA' flag, 
            # instead of one packet with 'FA' flag.0
            answered, unanswered = sr(packet, timeout=waitTime, verbose=self.isVerbose, multi=True)
            responses = [rcv for snd, rcv in answered]

            # Drop responses addressed to the wrong port — these are stale packets from a
            # previous test that used a different local port and arrived late.
            expected_dport = self.senderPort
            valid_responses = []
            for resp in responses:
                if resp['TCP'].dport != expected_dport:
                    print(f'*** Dropping stale packet: dport={resp["TCP"].dport} expected {expected_dport} ***')
                else:
                    valid_responses.append(resp)
            responses = valid_responses

            # Deduplicate retransmissions across all sr() calls within this test.
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

            if self.checkForDpiAlert(dpi_marker):
                self.last_dpi_rule = "RuleMatched"

                print("*** DPI detected the packet payload: " + self.last_dpi_rule + " ***")

            if len(responses) == 0:
                return Timeout()
            elif len(responses) == 1:
                response = responses[0] 
                label = self.intToFlags(int(response[TCP].flags))
                if response.haslayer(Raw):
                    payload_length = len(bytes(response[Raw].load))
                    if payload_length > 0:
                        label += f"_DATA_{payload_length}"
                self.response_flag_sequence = label
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
                    label = self.intToFlags(int(response[TCP].flags))

                    if response.haslayer(Raw):
                        payload_length = len(bytes(response[Raw].load))
                        if payload_length > 0:
                            label += f"_DATA_{payload_length}"

                    response_labels.append(label)

                self.response_flag_sequence = "|".join(response_labels)

                # Preserve seq, ack, and payload from the final normalized
                # response for the learner's TCP context.
                last_response = normalized_responses[-1]

                print(
                    f"*** Normalized responses: "
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

    @staticmethod
    def tcp_seq_before(left, right):
        """
        Return True when left is before right in TCP's 32-bit
        sequence-number space.

        This comparison is valid when the compared sequence numbers
        are less than 2**31 positions apart.
        """
        difference = (int(right) - int(left)) & 0xFFFFFFFF
        return 0 < difference < 0x80000000


    def merge_contiguous_responses(self, responses):
    
        if not responses:
            return None

        mask = 0xFFFFFFFF

        # Combining these flags could change their meaning.
        unsafe_flags = 0x04 | 0x20 | 0x40 | 0x80  # RST, URG, ECE, CWR

        for packet in responses:
            if int(packet[TCP].flags) & unsafe_flags:
                return None

        # Find the earliest TCP sequence number.
        start_seq = int(responses[0][TCP].seq)

        for packet in responses[1:]:
            packet_seq = int(packet[TCP].seq)

            if self.tcp_seq_before(packet_seq, start_seq):
                start_seq = packet_seq

        # Put the responses in TCP sequence order.
        ordered = sorted(
            responses,
            key=lambda packet: (
                int(packet[TCP].seq) - start_seq
            ) & mask
        )

        merged_flags = 0
        payload_parts = []
        next_seq = start_seq
        fin_seen = False
        syn_seen = False

        for packet in ordered:
            flags = int(packet[TCP].flags)
            packet_seq = int(packet[TCP].seq)

            payload = (
                bytes(packet[Raw].load)
                if packet.haslayer(Raw)
                else b""
            )

            has_syn = bool(flags & 0x02)
            has_fin = bool(flags & 0x01)

            merged_flags |= flags

            # ACK-only packets consume no sequence numbers.
            if not payload and not has_syn and not has_fin:
                continue

            # Payload/SYN/FIN packets must be consecutive.
            if packet_seq != next_seq:
                print(
                    '*** Cannot merge responses: '
                    f'expected seq={next_seq}, got seq={packet_seq} ***'
                )
                return None

            # Do not accept data or another control after FIN.
            if fin_seen:
                return None

            if has_syn:
                if syn_seen or packet_seq != start_seq:
                    return None

                syn_seen = True

            payload_parts.append(payload)

            # Data bytes, SYN, and FIN consume sequence numbers.
            consumed = len(payload)

            if has_syn:
                consumed += 1

            if has_fin:
                consumed += 1
                fin_seen = True

            next_seq = (next_seq + consumed) & mask

        merged_payload = b"".join(payload_parts)

        # Find the most advanced cumulative ACK.
        ack_packets = [
            packet
            for packet in ordered
            if int(packet[TCP].flags) & 0x10
        ]

        if ack_packets:
            latest_ack = int(ack_packets[0][TCP].ack)

            for packet in ack_packets[1:]:
                packet_ack = int(packet[TCP].ack)

                if self.tcp_seq_before(latest_ack, packet_ack):
                    latest_ack = packet_ack
        else:
            latest_ack = int(ordered[0][TCP].ack)

        # Start with a copy of the earliest response.
        merged = ordered[0].copy()

        merged[TCP].seq = start_seq
        merged[TCP].ack = latest_ack
        merged[TCP].flags = merged_flags

        # Replace its payload with the complete collected payload.
        merged[TCP].remove_payload()

        if merged_payload:
            merged[TCP].add_payload(Raw(load=merged_payload))

        flag_names = ", ".join(
            self.intToFlags(int(packet[TCP].flags))
            for packet in ordered
        )

        print(
            f'*** Merging responses: {flag_names} '
            f'-> {self.intToFlags(merged_flags)}; '
            f'payload length={len(merged_payload)} ***'
        )

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

    def checkForDpiAlert(self, marker):
        """
        Check whether Snort wrote a matching alert after the marker.
        """
        if self.dpiAlertsFile is None or marker is None:
            return False

        # Snort may write the alert asynchronously, so we wait a bit before reading the file.
        time.sleep(self.dpiWaitTime)

        try:
            current_size = os.path.getsize(self.dpiAlertsFile)

            # Handle a file that was cleared.
            if current_size < marker:
                marker = 0

            with open(self.dpiAlertsFile, 'r', encoding='utf-8', errors="replace") as alert_file:
                alert_file.seek(marker)
                new_alerts = alert_file.read()

        except OSError as error:
            raise RuntimeError(f"Failed to read DPI alert file: {self.dpiAlertsFile}. Error: {error}")

        # This is intentionally simple because there is currently one rule.
        return "Mapper send Data" in new_alerts


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
            global seqVar, ackVar
            seqVar = response.seq
            ackVar = response.ack
            self.lastRecvSeq = response.seq
            self.lastRecvAck = response.ack
        return response

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
        self.refreshNetworkPort()


    def shutdown(self):
        pass

# example on how to run the sender
if __name__ == "__main__":
    print("main test")
    sender = Sender(serverMAC="08:00:27:23:AA:AF", serverIP="131.174.142.227", serverPort=8000, useTracking=False, isVerbose=0, networkPortMinimum=20000, waitTime=1)
    seq = 50
    sender.refreshNetworkPort()
    sender.sendInput("S", seq, 1, '') #SA svar seq+1 | SYN_REC
    sender.sendInput("A", seq + 1, seqVar + 1, '') #A svar+1 seq+2 | CLOSE_WAIT
    sender.sendInput("FA", seq + 1, seqVar + 1, '')
