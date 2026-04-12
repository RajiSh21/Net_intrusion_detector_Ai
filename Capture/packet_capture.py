from scapy.all import get_if_list, sniff


def on_packet(packet):
    print(packet.summary(), flush=True)


interfaces = get_if_list()
print("Available interfaces:", interfaces)

if not interfaces:
    print("No interfaces found!")
else:
    # Let user choose an interface. Press Enter to use the first one.
    default_iface = interfaces[0]
    selected_iface = input(f"Enter interface name (default: {default_iface}): ").strip() or default_iface

    print(f"Listening on: {selected_iface}")
    print("Capturing up to 10 packets or stopping after 15 seconds...\n")

    packets = sniff(iface=selected_iface, prn=on_packet, count=10, timeout=15, store=False)
    print(f"\nCapture finished. Packets seen: {len(packets)}")