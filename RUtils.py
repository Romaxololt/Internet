import os

def str_to_bits(s):
    return ''.join(f'{ord(c):08b}' for c in s)

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
                Payload += " " * diff
            frame += str_to_bits(Payload)
            return frame

    @staticmethod
    def field_extract(frame):
        dst_mac = MAC.bits_to_mac(frame[0:48])
        src_mac = MAC.bits_to_mac(frame[48:96])
        eth_type = int(frame[96:112], 2)
        payload = bits_to_str(frame[112:])
        return {
            "Trame Type": "Ethernet II" if eth_type < 1536 else "IEEE 802.3",
            "Destination MAC": dst_mac,
            "Source MAC": src_mac,
            "EtherType": eth_type,
            "Payload": payload,
            "Length": len(frame)
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
            print("[+] Operating in switch mode as " + self.NIC)
        elif debug:
            print(f"[+] Operating in client mode as {self.NIC}")
        # only switch keeps a MAC table
        self.MAC_table = File.read_file(self.NIC.replace(":", "") + ".dat", typeof="dict") if self.ImSwitch else None

    def process(self):
        file_name = self.NIC.replace(":", "") + ".res"
        frames = File.read_file(file_name, typeof="port")
        for raw in frames:
            parsed = MAC.field_extract(raw)
            if self.debug:
                print(f"[<>] Processing frame by {self.NIC}:", parsed)

            if parsed["Destination MAC"] == self.NIC:
                print(f"[<] Delivered frame directly to {self.NIC}")
                continue

            # send raw frame string
            self.send(raw)

        # clear inbox
        with open(os.path.join("port", file_name), 'w') as f:
            f.write('')

        if self.debug:
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

    pc1 = RUtils("00:00:00:00:00:01", "00:00:00:00:00:00", debug=debug)
    pc1.Send_Raw_Payload("Test Frame", dest_mac="00:00:00:00:00:02", OSI2_Protocol="Ethernet II")
    pc2 = RUtils("00:00:00:00:00:02", "00:00:00:00:00:00", debug=debug)
    pc2.process()
