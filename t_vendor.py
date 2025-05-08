from mac_vendors import mac_vendors

# Példa a használatra
mac = "00:00:00"
if mac in mac_vendors:
    print(f"Gyártó: {mac_vendors[mac]}")
else:
    print("A MAC-cím nem található.")
