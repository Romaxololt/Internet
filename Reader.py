import RUtils
import os
mac = "00:00:00:00:00:00"
filename = mac.replace(":", "") + ".res"
file = os.path.join(os.getcwd(), "port", filename)
frames = RUtils.File.read_file(file)
for raw in frames:
    print(RUtils.MAC.field_extract(raw))

