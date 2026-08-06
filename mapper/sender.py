from scapy.all import sr, sr1, IP, TCP, Raw
from response import Timeout, ConcreteResponse
import re
import time
import random

# variables used to retain last sequence/acknowledgment sent
seqVar = 0
ackVar = 0

dpi_alerts_file = "/var/log/snort/alert_fast.txt"

class Sender:
    """This class contains functions for creating and sending TCP packets. It communicates with the learner via the learnerSocket class"""

    def __init__(self, serverMAC=None, serverIP="191.168.10.1", serverPort = 7991,
             networkInterface="lo", networkInterfaceType=0, senderPort=15000, senderPortMinimum=20000,
             senderPortMaximum=40000, portNumberFile = "sn.txt",
             isVerbose=0, waitTime=0.1, resetMechanism=0): # increased default waitTime of server to 0.1 to capture multiple responses (sr)
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
        self.last_dpi_message = None
        self.last_dpi_rule = None

        # Tracks seen packets (by seq/ack/flags) across all sr() calls within one test,
        # cleared on reset so duplicates/retransmissions within a test are filtered out.
        self.response_history = set()

        # start with a clean DPI alert file for each mapper run
        self.clearDPIAlertFile(dpi_alerts_file)


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

        if packet is not None:
            self.clientIP = packet[IP].src
            dpi_marker = self.DPI_monitor(dpi_alerts_file, 'before')

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

            dpi_message = self.DPI_monitor(dpi_alerts_file, 'after', marker=dpi_marker)
            self.last_dpi_message = dpi_message
            dpi_rule = ''
            # print(f'*** DPI alert message: {dpi_message} ***')
            if dpi_message is not None and dpi_message == "Mapper send Data":
                dpi_rule = "RuleMatched"
            self.last_dpi_rule = dpi_rule if dpi_rule else None

            if len(responses) == 0:
                return Timeout()
            elif len(responses) == 1:
                response = responses[0] 
                return response
            else: #len (responses) > 1: multiple replies
                base_seq = responses[0]['TCP'].seq
                base_ack = responses[0]['TCP'].ack

                # if all responses share the same seq and ack numbers,merge them into one response with combined flags.
                if all(pkt['TCP'].seq == base_seq and pkt['TCP'].ack == base_ack for pkt in responses):
                    merged_responses = self.merge_responses(responses)
                else:
                    # TODO: Handle the case where responses have different seq/ack numbers.
                    # This can happen if the server sends multiple distinct packets (e.g., A then FA
                    # with incremented seq). For now, fall back to the packet with the highest seq.
                    print('Bug: multiple responses with different seq/ack — falling back to highest seq packet')
                    merged_responses = max(responses, key=lambda pkt: pkt['TCP'].seq)
                return merged_responses

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

    def clearDPIAlertFile(self, filename):
        """Clear the DPI alert file at mapper startup."""
        try:
            with open(filename, 'w'):
                pass
            print("Cleared DPI alert file: " + filename)
        except (PermissionError, OSError) as e:
            print("Warning: could not clear DPI alert file '" + filename + "': " + str(e))
    
    def DPI_monitor(self, filename, phase, marker=None):
        """Read DPI alert file. 
        phase 'before': mark last line count.
        phase 'after': check if new alert added since marker, return message or None."""
        try:
            with open(filename, 'r') as f:
                lines = f.readlines()
            if phase == 'before':
                return len(lines)
            elif phase == 'after':
                if marker is None:
                    return None
                new_lines = lines[marker:]
                if new_lines:
                    for line in new_lines:
                        match = re.search(r'\[\*\*\]\s*\[[^\]]+\]\s*"([^"]+)"\s*\[\*\*\]', line)
                        if match:
                            message = match.group(1)
                            print(message)
                            return message
                    print("new_lines[-1].strip() " + new_lines[-1].strip())
                    return new_lines[-1].strip()
                return None
        except FileNotFoundError:
            return None
            
    
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
