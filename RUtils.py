import os
from colorama import Fore, Style, init, Back
import time

init(autoreset=True)

Protocol_Ethertype = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6"
}


def str_to_bits(s):
    return ''.join(f'{ord(c):08b}' for c in s)


def str_to_RBinary(s):
    val = 0
    for i in range(len(s)):
        val = val << 1
        if s[i] == "1":
            val = val | 1
    return val


def bits_to_str(b):
    chars = [b[i:i+8] for i in range(0, len(b), 8)]
    return ''.join(chr(int(char, 2)) for char in chars)


# ------------------ Beautify / logging helper ------------------

def bprint(need_level, nic, current_level, text, fore=None, back=None, bright=False, prefix=None):
    """Centralized printing function for all beautify outputs.

    - need_level: minimal beautify level required to show the message
    - nic: identifier used in the prefix (usually the NIC string)
    - current_level: the instance's beautify level
    - text: message to print
    - fore/back/bright: colorama attributes (optional)
    - prefix: if provided, uses that instead of timestamped prefix
    """
    # preserve original behaviour: if need_level == 0 -> always print
    if need_level != 0 and current_level < need_level:
        return

    parts = []
    if fore:
        parts.append(fore)
    if back:
        parts.append(back)
    if bright:
        parts.append(Style.BRIGHT)

    if prefix is None:
        timestamp = time.strftime("%H:%M:%S")
        header = f"[{timestamp}]({nic}) "
    else:
        header = prefix

    print(''.join(parts) + header + str(text))


class File:
    @staticmethod
    def read_file(file_path, typeof="port"):
        if typeof == "port":
            file_path = os.path.join(os.getcwd(), "port", file_path)
            if not os.path.exists(file_path):
                return []
            with open(file_path, 'r') as file:
                content = file.readlines()
            content = [line.strip() for line in content]
            return content
        elif typeof == "dict":
            file_path = os.path.join(os.getcwd(), "dat", file_path)
            if not os.path.exists(file_path):
                return []
            with open(file_path, 'r') as file:
                content = file.readlines()
            lines = [line.strip() for line in content]
            return lines

    @staticmethod
    def add_line(file_path, line, typeof="port"):
        """Appends or updates a line in a file (port = list of lines, dict = key=value store)."""
        if typeof == "port":
            content = File.read_file(file_path, "port")  # liste
            content.append(line)
            file_path = os.path.join(os.getcwd(), "port", file_path)
            with open(file_path, 'w') as f:
                f.write('\n'.join(content) + '\n')
    
    @staticmethod
    def save_list(file_path, lst):
        if lst is None:
            lst = []
        file_path = os.path.join(os.getcwd(), "dat", file_path)
        with open(file_path, 'w') as f:
            for item in lst:
                f.write(f"{item}\n")

    @staticmethod
    def save_dict(file_path, dct):
        if dct is None:
            dct = {}
        file_path = os.path.join(os.getcwd(), "dat", file_path)
        with open(file_path, 'w') as f:
            for key, value in dct.items():
                f.write(f"{key}={value}\n")


class MAC:
    @staticmethod
    def mac_to_bits(mac):
        """Converts a MAC address string to its binary representation."""
        mac_bytes = bytes(int(b, 16) for b in mac.split(':'))
        return ''.join(f'{byte:08b}' for byte in mac_bytes)

    @staticmethod
    def bits_to_mac(bits):
        """Converts a binary representation to a MAC address string."""
        mac_bytes = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
        return ':'.join(f'{byte:02X}' for byte in mac_bytes).upper()

    @staticmethod
    def build(NIC_Src, NIC_Dest, Type, Payload, OSI2_Protocol="Ethernet II"):
        frame = ""
        if OSI2_Protocol == "Ethernet II":
            frame += MAC.mac_to_bits(NIC_Dest)
            frame += MAC.mac_to_bits(NIC_Src)
            frame += f"{Type:016b}"
            if len(Payload) < 46:
                diff = 46 - len(Payload)
                Payload += 0x00 * diff
            frame += str_to_bits(Payload)
            return frame

        if OSI2_Protocol == "IEEE 802.3":
            frame += MAC.mac_to_bits(NIC_Dest)
            frame += MAC.mac_to_bits(NIC_Src)
            payload_len_bytes = len(Payload)
            frame += f"{payload_len_bytes:016b}"
            if payload_len_bytes < 46:
                diff = 46 - payload_len_bytes
                Payload += 0x00 * diff
            frame += str_to_bits(Payload)
            return frame

    @staticmethod
    def field_extract(frame):
        dst_mac = MAC.bits_to_mac(frame[0:48])
        src_mac = MAC.bits_to_mac(frame[48:96])
        eth_type = int(frame[96:112], 2)
        payload = bits_to_str(frame[112:])
        return {
            "Trame Type": "Ethernet II" if eth_type > 1536 else "IEEE 802.3",
            "Destination MAC": dst_mac,
            "Source MAC": src_mac,
            "EtherType" if eth_type > 1536 else "Length": eth_type,
            "Payload": payload,
            "Length": len(frame),
            "Protocol": Protocol_Ethertype.get(eth_type, "Unknown")
        }

    @staticmethod
    def flood(switch_mac):
        """Return list of MACs (with :) present in port folder, excluding the switch itself."""
        flood = []
        sm = switch_mac.replace(":", "")
        for _, _, files in os.walk(os.path.join(os.getcwd(), "port")):
            for file in files:
                if not file.endswith(".res"):
                    continue
                mac_noext = file.replace(".res", "")
                if mac_noext == sm:
                    continue  # ignore the switch itself
                # format with colons
                mac = ":".join(mac_noext[i:i+2] for i in range(0, len(mac_noext), 2))
                flood.append(mac)
        return flood


class ARP:
    @staticmethod
    def build(opcode, sender_mac, sender_ip, target_mac, target_ip, hw_type=1, proto_type=0x0800, hw_size=6, proto_size=4):
        arp_packet = ""
        arp_packet += f"{hw_type:016b}"
        arp_packet += f"{proto_type:016b}"
        arp_packet += f"{hw_size:08b}"
        arp_packet += f"{proto_size:08b}"
        arp_packet += f"{opcode:016b}"
        arp_packet += MAC.mac_to_bits(sender_mac)
        arp_packet += IPv4.ip_to_bits(sender_ip)
        arp_packet += MAC.mac_to_bits(target_mac)
        arp_packet += IPv4.ip_to_bits(target_ip)
        return arp_packet
    
    @staticmethod
    def parse(arp_packet):
        hw_type = int(arp_packet[0:16], 2)
        proto_type = int(arp_packet[16:32], 2)
        hw_size = int(arp_packet[32:40], 2)
        proto_size = int(arp_packet[40:48], 2)
        opcode = int(arp_packet[48:64], 2)
        sender_mac = MAC.bits_to_mac(arp_packet[64:112])
        sender_ip = IPv4.bits_to_ip(arp_packet[112:144])
        target_mac = MAC.bits_to_mac(arp_packet[144:192])
        target_ip = IPv4.bits_to_ip(arp_packet[192:224])
        return {
            "Hardware Type": hw_type,
            "Protocol Type": proto_type,
            "Hardware Size": hw_size,
            "Protocol Size": proto_size,
            "Opcode": opcode,
            "Sender MAC": sender_mac,
            "Sender IP": sender_ip,
            "Target MAC": target_mac,
            "Target IP": target_ip
        }
        
    @staticmethod
    def explain(arp_packet):
        parsed = ARP.parse(arp_packet)
        
        print("ARP Packet:")
        if parsed["Opcode"] == 1:
            print("  Operation: Request")
        elif parsed["Opcode"] == 2:
            print("  Operation: Reply")
        else:
            print(f"  Operation: Unknown ({parsed['Opcode']})")
        print(f"  Sender MAC Address: {parsed['Sender MAC']}")
        print(f"  Sender IP Address: {parsed['Sender IP']}")
        if parsed["Target MAC"] == "00:00:00:00:00:00":
            print("  Target MAC Address: (unknown)")
        else:
            print(f"  Target MAC Address: {parsed['Target MAC']}")


class IPv4:
    @staticmethod
    def bits_to_ip(bits):
        return '.'.join(str(int(bits[i:i+8], 2)) for i in range(0, 32, 8))
    
    @staticmethod
    def ip_to_bits(ip):
        return ''.join(f'{int(part):08b}' for part in ip.split('.'))
    
    @staticmethod
    def fragment(paquet, MTU=1500):

        if len(paquet)//8 < MTU:
            return [paquet]

        paquetUnpack = IPv4.unpacket(paquet)
        headerSize = paquetUnpack["Header Length"]
        payloadSize =  paquetUnpack["Total Length"] - headerSize
        maxDataSize = MTU - headerSize
        fragments = []
        offset = 0

        while payloadSize > 0:
            if payloadSize > maxDataSize:
                FragSize = maxDataSize
                MF = 1
            else:
                FragSize = payloadSize
                MF = 0

            ihl_words = paquetUnpack.get("IHL_words", paquetUnpack["Header Length"]//4)
            fragment = IPv4.packet_build(
                paquetUnpack["Source IP"],
                paquetUnpack["Destination IP"],
                paquetUnpack["Payload"][offset:offset+FragSize],
                ident= paquetUnpack["Identification"],
                tos= paquetUnpack["Type of Service"],
                ihl= ihl_words,
                ttl= paquetUnpack["TTL"],
                fragment_offset= offset,
                protocol= paquetUnpack["Protocol"],
                MF=MF,
                DF = ((paquetUnpack["Flags"] >> 14) & 1)
            )
            fragments.append(fragment)
            offset += FragSize
            payloadSize -= FragSize

        return fragments

    @staticmethod
    def checksum(header_bits: str):
        # convertir la chaîne de bits en tableau de bytes
        header_bytes = [int(header_bits[i:i+8], 2) for i in range(0, len(header_bits), 8)]

        s = 0
        for i in range(0, len(header_bytes), 2):
            mot = (header_bytes[i] << 8) + (header_bytes[i+1] if i+1 < len(header_bytes) else 0)
            s += mot
            s = (s & 0xFFFF) + (s >> 16)

        return (~s) & 0xFFFF

    @staticmethod
    def unpacket(packet):
        """
        Unpacks an IPv4 packet from a string of bits.

        Returns a dictionary containing the following fields:
            - Version
            - Header Length
            - Type of Service
            - Total Length
            - Identification
            - Flags
            - TTL
            - Protocol
            - Checksum
            - Source IP
            - Destination IP
            - Payload
            - check: a boolean indicating whether the checksum is correct
        """
        # dans IPv4.unpacket (remplacer la partie existante de parsing)
        ver_ihl = packet[:8]
        ver = int(ver_ihl[:4], 2)
        ihl_words = int(ver_ihl[4:], 2)               # nombre de mots (4-octets)
        ihl = ihl_words * 4                           # header length en octets
        tos = packet[8:16]
        total_len = packet[16:32]
        ident = packet[32:48]
        flags_field = packet[48:64]                   # 16 bits : 3 flags + 13 offset
        flag_bits = flags_field[:3]
        reserved = int(flag_bits[0], 2)
        DF = int(flag_bits[1], 2)
        MF = int(flag_bits[2], 2)
        frag_offset_units = int(flags_field[3:], 2)   # en blocs de 8 octets
        frag_offset_bytes = frag_offset_units * 8

        ttl = packet[64:72]
        protocol = packet[72:80]
        checksum = packet[80:96]
        src_ip = IPv4.bits_to_ip(packet[96:128])
        dst_ip = IPv4.bits_to_ip(packet[128:160])
        # rebuild header for checksum (checksum field = 0)
        header = packet[:80] + "0000000000000000" + packet[96:160]
        payload = bits_to_str(packet[160:])

        return {
            "Version": ver,
            "Header Length": ihl,                   # en octets (comme tu faisais)
            "IHL_words": ihl_words,                 # utile pour reconstruire
            "Type of Service": int(tos, 2),
            "Total Length": int(total_len, 2),
            "Identification": int(ident, 2),
            "Flags": int(flags_field, 2),
            "MF": MF,
            "DF": DF,
            "Fragment Offset": frag_offset_bytes,   # renvoie en octets (plus lisible)
            "TTL": int(ttl, 2),
            "Protocol": int(protocol, 2),
            "Checksum": int(checksum, 2),
            "Source IP": src_ip,
            "Destination IP": dst_ip,
            "Payload": payload,
            "check": IPv4.checksum(header) == int(checksum, 2)
        }

    
    @staticmethod
    def packet_build(src_ip, dst_ip, payload,ident, ihl=5, tos=0, ttl=64,fragment_offset=0, protocol=6, MF=0, DF=0):
        """
        Builds an IPv4 packet from its constituent parts.

        Parameters:
            src_ip (str): the source IP address
            dst_ip (str): the destination IP address
            payload (str): the payload of the packet
            ident (int): the identification field of the packet
            ihl (int): the header length of the packet
            tos (int): the type of service field of the packet
            ttl (int): the time to live field of the packet
            fragment_offset (int): the fragment offset field of the packet
            protocol (int): the protocol field of the packet
            MF (int): the more fragments flag of the packet
            DF (int): the do not fragment flag of the packet

        Returns:
            str: the built packet as a string of bits
        """
        ver_ihl = f"{(4<<4 | ihl):08b}"
        tos = f"{tos:08b}"
        payloadBytes = payload.encode()
        total_len = f"{len(payloadBytes) + 20:016b}"
        ident = f"{ident:016b}"
        flags = (0 << 15) | (DF << 14) | (MF << 13) | (fragment_offset >> 3)
        flags = f"{flags:016b}"
        ttl = f"{ttl:08b}"
        protocol = f"{protocol:08b}"
        checksum = f"{0:016b}"
        src_ip = f"{IPv4.ip_to_bits(src_ip)}"
        dst_ip = f"{IPv4.ip_to_bits(dst_ip)}"
        header = ver_ihl + tos + total_len + ident + flags + ttl + protocol + checksum + src_ip + dst_ip
        checksum = f"{IPv4.checksum(header):016b}"
        payload = str_to_bits(payload)
        return ver_ihl + tos + total_len + ident + flags + ttl + protocol + checksum + src_ip + dst_ip + payload


class RUtils:
    def __init__(self, NIC, SWITCH_MAC, IP, ident = 0, beautify=0, ARP_Gratuitous_On_start=True, MTU=1500):
        """
        Initializes an RUtils object with the given Network Interface Card (NIC) and switch MAC address.
        """
        self.MTU = MTU
        self.NIC = NIC
        self.SWITCH_MAC = SWITCH_MAC
        self.IP = IP

        tmpARP = File.read_file(NIC.replace(":", "") + ".arp", typeof="dict")
        self.ARP_Cache = {}
        for entry in tmpARP:
            self.ARP_Cache[entry.split("=")[0]] = [entry.split("=")[1], entry.split("=")[2]]

        self.ident = ident
        # ensure port file exists
        port_file = os.path.join(os.getcwd(), "port", self.NIC.replace(":", "") + ".res")
        os.makedirs(os.path.dirname(port_file), exist_ok=True)
        if not os.path.exists(port_file):
            with open(port_file, 'w') as f:
                f.write('')
        self.ImSwitch = (NIC == SWITCH_MAC)
            
        self.beautify = beautify
        
        # pretty prints using centralized helper (keeps behaviour identical but nicer formatting)
        if self.beautify >= 1:
            extra = "\n" if not self.ImSwitch else ""
            bprint(1, self.NIC, self.beautify, f"[i] initialized for NIC {self.NIC} with switch {self.SWITCH_MAC}{extra}", fore=Fore.GREEN, bright=True)
            
        if self.beautify >= 2:
            bprint(2, self.NIC, self.beautify, f"[i] IP address set to {self.IP}", fore=Fore.YELLOW, bright=True)

        if self.beautify >= 5:
            bprint(5, self.NIC, self.beautify, f"[i] ARP cache: {self.ARP_Cache}", fore=Fore.BLUE, bright=True)
        if self.ImSwitch and self.beautify >= 1:
            bprint(1, self.NIC, self.beautify, f"[i] operating as switch", fore=Fore.CYAN, bright=True)

        # only switch keeps a MAC table
        self.MAC_table = File.read_file(self.NIC.replace(":", "") + ".mac", typeof="dict") if self.ImSwitch else None

        if ARP_Gratuitous_On_start:
            bprint(3, self.NIC, self.beautify, f"[i] Sending gratuitous ARP on start : {self.IP} -> {self.NIC}", fore=Fore.BLACK, back=Back.YELLOW)
            self.send(self.Build_ARP_Gratuitous())

    def Constant_Process(self, timeout=1):
        while True:
            self.process()
            time.sleep(timeout)
        
    def process(self):
        file_name = self.NIC.replace(":", "") + ".res"
        frames = File.read_file(file_name, typeof="port")
        for raw in frames:
            parsed = MAC.field_extract(raw)
            if self.beautify >= 5:
                if not self.ImSwitch:
                    bprint(5, self.NIC, self.beautify, f"[<>] processing frame: {parsed['Protocol']}", fore=Fore.MAGENTA, bright=True)
                else:
                    bprint(5, self.NIC, self.beautify, f"[<>] Switch processing frame: {parsed['Protocol']}", fore=Fore.MAGENTA, bright=True)

            if parsed["Destination MAC"] == self.NIC or (parsed["Destination MAC"] == "FF:FF:FF:FF:FF:FF"): #* IF FOR ME OR BROADCAST
                #* Protocol Verif
                if parsed["Protocol"] == "ARP": #* IF ARP
                    if self.beautify >= 4:
                        bprint(4, self.NIC, self.beautify, f"[<] received ARP packet", fore=Fore.BLUE, bright=True)
                    Arp_parsed = ARP.parse(parsed["Payload"])
                    if Arp_parsed["Opcode"] == 1 and Arp_parsed["Target IP"] == self.IP: #* IF ARP REQUEST
                        if self.beautify >= 4:
                            bprint(4, self.NIC, self.beautify, f"[<] received ARP request from {Arp_parsed['Sender IP']}", fore=Fore.BLUE, bright=True)
                        arp_reply = ARP.build(
                            opcode=2,
                            sender_mac=self.NIC,
                            sender_ip=self.IP,
                            target_mac=Arp_parsed["Sender MAC"],
                            target_ip=Arp_parsed["Sender IP"]
                        )
                        # preserve original call to send (keeps logic intact)
                        self.Send(self.Build_Raw_Payload(arp_reply, dest_mac=Arp_parsed["Sender MAC"], OSI2_Protocol="Ethernet II", EtherType=0x0806))
                        if self.beautify >= 4:
                            bprint(4, self.NIC, self.beautify, f"[>] sending ARP-reply", fore=Fore.BLACK, back=Back.GREEN)
                    elif Arp_parsed["Opcode"] == 2 and Arp_parsed["Target IP"] == self.IP: #* IF ARP REPLY

                        if self.beautify >= 4:
                            bprint(4, self.NIC, self.beautify, f"[<] received ARP reply from {Arp_parsed['Sender IP']}, MAC: {Arp_parsed['Sender MAC']}", fore=Fore.BLACK, back=Back.BLUE)

                        self.ARP_Cache[Arp_parsed["Sender IP"]] = [Arp_parsed["Sender MAC"] , time.time() + 120]
                    elif Arp_parsed["Opcode"] == 1 and Arp_parsed["Sender IP"] == Arp_parsed["Target IP"]: #* IF GRATUITOUS ARP
                        # on met à jour l'ARP cache
                        self.ARP_Cache[Arp_parsed["Sender IP"]] = [Arp_parsed["Sender MAC"], time.time() + 120]
                        if self.beautify >= 4:
                            bprint(4, self.NIC, self.beautify, f"[i] learned gratuitous ARP: {Arp_parsed['Sender IP']} -> {Arp_parsed['Sender MAC']}", fore=Fore.BLUE)
                        if self.ImSwitch:
                            self.send(raw)
                
                continue
            
            else: #* NOT FOR ME
                if self.ImSwitch:
                    self.send(raw)
                    
        #* TRAITEMENT FINI

        # clear inbox
        with open(os.path.join("port", file_name), 'w') as f:
            f.write('')

        # persist ARP table

        for key in list(self.ARP_Cache.keys()):
            if time.time() > float(self.ARP_Cache[key][1]):
                del self.ARP_Cache[key]
            else:
                if self.beautify >= 4:
                    bprint(4, self.NIC, self.beautify, f"[i] Time left for {key} in seconds: {float(self.ARP_Cache[key][1]) - time.time()}", fore=Fore.BLUE)


        lst_to_save = []
        for entry in self.ARP_Cache:
            lst_to_save.append(f"{entry}={self.ARP_Cache[entry][0]}={self.ARP_Cache[entry][1]}")

        os.makedirs(os.path.join(os.getcwd(), "dat"), exist_ok=True)
        File.save_list(self.NIC.replace(":", "") + ".arp", lst_to_save)

        # persist MAC table only if switch
        if self.ImSwitch:
            os.makedirs(os.path.join(os.getcwd(), "dat"), exist_ok=True)
            File.save_list(self.NIC.replace(":", "") + ".mac", self.MAC_table)

    def send(self, frame, force_dest=None):
        """
        Sends a frame to its destination according to the MAC table.
        """
        frame_data = MAC.field_extract(frame)
        dst = frame_data["Destination MAC"] if force_dest is None else force_dest
        src = frame_data["Source MAC"]

        # SWITCH MODE
        if self.ImSwitch:
            # learn source MAC
            if src not in self.MAC_table:
                self.MAC_table.append(src)
            if dst == "FF:FF:FF:FF:FF:FF":
                # broadcast
                for mac in MAC.flood(self.SWITCH_MAC):
                    if mac == src:
                        continue
                    if mac == self.SWITCH_MAC:
                        continue
                    File.add_line(mac.replace(":", "") + ".res", frame)
                return

            # known destination -> forward directly
            if dst in self.MAC_table:
                File.add_line(dst.replace(":", "") + ".res", frame)
                return

            # unknown destination -> flood (excluding source and the switch itself)
            flood_list = MAC.flood(self.SWITCH_MAC)
            for mac in flood_list:
                if mac != src:
                    File.add_line(mac.replace(":", "") + ".res", frame)
            return

        # CLIENT MODE: always send frames to the switch
        else:
            File.add_line(self.SWITCH_MAC.replace(":", "") + ".res", frame)
            return

    def Build_Raw_Payload(self, payload, dest_mac=None, OSI2_Protocol="Ethernet II", EtherType=0x0800):
        if dest_mac is not None:
            frame = MAC.build(self.NIC, dest_mac, Type=EtherType, Payload=payload, OSI2_Protocol=OSI2_Protocol)
        else:
            frame = MAC.build(self.NIC, self.SWITCH_MAC, Type=EtherType, Payload=payload, OSI2_Protocol=OSI2_Protocol)
        return frame

    def Build_ARP_Raw_Payload(self, opcode, target_ip, target_mac="00:00:00:00:00:00"):
        sender_mac = self.NIC
        sender_ip = self.IP
        ARP_paquet = ARP.build(
            opcode=opcode,
            sender_mac=sender_mac,
            sender_ip=sender_ip,
            target_mac=target_mac,
            target_ip=target_ip)
        return self.Build_Raw_Payload(ARP_paquet, dest_mac="FF:FF:FF:FF:FF:FF", OSI2_Protocol="Ethernet II", EtherType=0x0806)

    def Build_ARP_Gratuitous(self):
        arp_packet = ARP.build(
            opcode=1,                     # ARP Request
            sender_mac=self.NIC,
            sender_ip=self.IP,
            target_mac="00:00:00:00:00:00",
            target_ip=self.IP            # ici on cible NOTRE propre IP
        )

        # envoi en broadcast comme toutes les gratuitous
        return self.Build_Raw_Payload(
            arp_packet,
            dest_mac="FF:FF:FF:FF:FF:FF",
            OSI2_Protocol="Ethernet II",
            EtherType=0x0806
        )

    def Build_To_IPv4(self, payload, dest_ip, ttl=64, protocol=1, tos=0, MF=0, DF=0):
        """
        Builds an IPv4 packet from its constituent parts and the destination IP address.

        Parameters:
            payload (str): the payload of the packet
            dest_ip (str): the destination IP address
            ttl (int): the time to live field of the packet (default: 64)
            protocol (int): the protocol field of the packet (default: ICMP = 1)
            tos (int): the type of service field of the packet (default: 0)
            MF (int): the more fragments flag of the packet (default: 0)
            DF (int): the do not fragment flag of the packet (default: 0)

        Returns:
            list: a list of frames to send on the network
        """
        frame_to_ret = []
        packet = IPv4.packet_build(
            src_ip=self.IP,
            dst_ip=dest_ip,
            payload=payload,
            ident=self.ident,
            ttl=ttl,
            tos=tos,
            protocol=protocol,  # ICMP
            MF=MF,
            DF=DF)
        
        frame_to_ret = IPv4.fragment(packet, MTU=self.MTU)
        
        if dest_ip in self.ARP_Cache:
            dest_mac = self.ARP_Cache[dest_ip][0]
        else:
            bprint(3, self.NIC, self.beautify, f"[!] Destination IP {dest_ip} not in ARP cache. Cannot build frame.", fore=Fore.RED, bright=True)
            return []
        
        final_frames = []
        for frame in frame_to_ret:
            final_frames.append(self.Build_Raw_Payload(frame, dest_mac=dest_mac, OSI2_Protocol="Ethernet II", EtherType=0x0800))
            
        return final_frames

if __name__ == "__main__":
    beautify = 10
    switch_mac = "00:00:00:00:00:FF"
    
    pc0 = RUtils("00:00:00:00:00:03", "00:00:00:00:00:FF", "0.0.0.3", beautify=beautify)
    #pc0.Send
    #pc0.Send_ARP_Raw_Payload(1, "0.0.0.2")
    pc0.process()
    input()
    
    switch = RUtils("00:00:00:00:00:FF", "00:00:00:00:00:FF", "0.0.0.0", beautify=beautify)
    switch.process()
    input()

    pc1 = RUtils("00:00:00:00:00:02", "00:00:00:00:00:FF", "0.0.0.1", beautify=beautify)
    pc1.process()
    input()
    switch.process()
