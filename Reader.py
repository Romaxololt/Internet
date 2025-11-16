import RUtils
import os
mac = "00:00:00:00:00:02"
filename = mac.replace(":", "") + ".res"
file = os.path.join(os.getcwd(), "port", filename)
frames = RUtils.File.read_file(file)
for raw in frames:
    raw = RUtils.MAC.field_extract(raw)
    payload = raw["Payload"]
    if raw["Protocol"] == "ARP":
        parsed = RUtils.ARP.parse(payload)
        RUtils.ARP.explain(payload)
    print(raw)

