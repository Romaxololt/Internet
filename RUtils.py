import os

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
        if typeof == "dict":
            content = line
            file_path = os.path.join(os.getcwd(), "dat", file_path)
            with open(file_path, 'w') as f:
                f.write('\n'.join(content) + '\n')

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
            frame += str_to_bits(Payload)
            return frame

        if OSI2_Protocol == "IEEE 802.3":
            frame += MAC.mac_to_bits(NIC_Dest)
            frame += MAC.mac_to_bits(NIC_Src)
            payload_len_bytes = len(Payload)
            frame += f"{payload_len_bytes:016b}"
            if payload_len_bytes < 46:
                diff = 46 - payload_len_bytes
                Payload += "0" * diff
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
    def __init__(self, NIC, SWITCH_MAC, debug=False):
        self.NIC = NIC
        self.SWITCH_MAC = SWITCH_MAC
        self.debug = debug
        # ensure port file exists
        port_file = os.path.join(os.getcwd(), "port", self.NIC.replace(":", "") + ".res")
        os.makedirs(os.path.dirname(port_file), exist_ok=True)
        if not os.path.exists(port_file):
            with open(port_file, 'w') as f:
                f.write('')
        self.ImSwitch = (NIC == SWITCH_MAC)
        if debug and self.ImSwitch:
            print("\n[+] Operating in switch mode as " + self.NIC)
        elif debug:
            print(f"\n[+] Operating in client mode as {self.NIC}")
        # only switch keeps a MAC table
        self.MAC_table = File.read_file(self.NIC.replace(":", "") + ".dat", typeof="dict") if self.ImSwitch else None

    def process(self):
        file_name = self.NIC.replace(":", "") + ".res"
        frames = File.read_file(file_name, typeof="port")
        for raw in frames:
            parsed = MAC.field_extract(raw)
            if self.debug:
                print(f"[<>] Processing frame by {self.NIC}:", parsed)

            if parsed["Destination MAC"] == self.NIC and not self.ImSwitch or (parsed["Destination MAC"] == "FF:FF:FF:FF:FF:FF" and not self.ImSwitch):
                print(f"[<] Delivered frame directly to {self.NIC}")
                continue

            # send raw frame string
            self.send(raw)

        # clear inbox
        with open(os.path.join("port", file_name), 'w') as f:
            f.write('')

        if self.debug and self.ImSwitch:
            print(f"[i] MAC table for {self.NIC}: {self.MAC_table}")

        # persist MAC table only if switch
        if self.ImSwitch:
            os.makedirs(os.path.join(os.getcwd(), "dat"), exist_ok=True)
            if len(self.MAC_table) == 1:
                self.MAC_table = [self.MAC_table]
            for i in self.MAC_table:
                File.add_line(self.NIC.replace(":", "") + ".dat", i, typeof="dict")

    def send(self, frame):
        frame_data = MAC.field_extract(frame)
        dst = frame_data["Destination MAC"]
        src = frame_data["Source MAC"]

        # SWITCH MODE
        if self.ImSwitch:
            # learn source MAC
            if src not in self.MAC_table:
                self.MAC_table.append(src)
                if self.debug:
                    print(f"[i] Switch learned MAC address: {src}")

            if dst == "FF:FF:FF:FF:FF:FF":
                # broadcast
                for mac in MAC.flood(self.SWITCH_MAC):
                    if mac == src:
                        continue
                    if mac == self.SWITCH_MAC:
                        continue
                    File.add_line(mac.replace(":", "") + ".res", frame)
                    if self.debug:
                        print(f"[>] Switch flooded frame to {mac} because broadcast")
                return

            # known destination -> forward directly
            if dst in self.MAC_table:
                File.add_line(dst.replace(":", "") + ".res", frame)
                if self.debug:
                    print(f"[>] Switch forwarded frame to known destination {dst}")
                return

            # unknown destination -> flood (excluding source and the switch itself)
            flood_list = MAC.flood(self.SWITCH_MAC)
            for mac in flood_list:
                if mac != src:
                    File.add_line(mac.replace(":", "") + ".res", frame)
                    if self.debug:
                        print(f"[>] Switch flooded frame to {mac} because destination unknown")
            return

        # CLIENT MODE: always send frames to the switch
        else:
            File.add_line(self.SWITCH_MAC.replace(":", "") + ".res", frame)
            if self.debug:
                print(f"[>] Client sent frame to switch {self.SWITCH_MAC}")
            return

    def Send_Raw_Payload(self, payload, dest_mac=None, OSI2_Protocol="Ethernet II"):
        if dest_mac is not None:
            frame = MAC.build(self.NIC, dest_mac, Type=0x0800, Payload=payload, OSI2_Protocol=OSI2_Protocol)
        else:
            frame = MAC.build(self.NIC, self.SWITCH_MAC, Type=0x0800, Payload=payload, OSI2_Protocol=OSI2_Protocol)
        self.send(frame)


if __name__ == "__main__":
    debug = True
    switch = RUtils("00:00:00:00:00:00", "00:00:00:00:00:00", debug=debug)
    switch.process()

    pc0 = RUtils("00:00:00:00:00:03", "00:00:00:00:00:00", debug=debug)
    pc0.process()
    pc1 = RUtils("00:00:00:00:00:02", "00:00:00:00:00:00", debug=debug)
    pc1.process()
    pc2 = RUtils("00:00:00:00:00:01", "00:00:00:00:00:00", debug=debug)
    pc2.process()

    paquet = IPv4.packet_build("1.1.1.1", "2.2.2.2", "Hello World 0123456789101112233445566778899", 0)
    print(paquet)
    print(IPv4.unpacket(paquet))
    input()
    frags = IPv4.fragment(paquet, MTU=28)
    for f in frags:
        print(IPv4.unpacket(f))
