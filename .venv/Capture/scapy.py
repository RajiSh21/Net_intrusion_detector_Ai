from scapy.all import sniff, get_if_list
print("Availablee interfaces:", get_if_list())

sniff(iface="Wi-Fi", prn=lambda x: x.summary(), count=10)