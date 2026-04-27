from scapy.all import get_if_list


def hello_world() -> str:
    return "hello world"


def choose_interface() -> str:
    interfaces = get_if_list()
    for i, iface in enumerate(interfaces):
        print(f"  {i}: {iface}")
    idx = int(input("Choose interface number: "))
    return interfaces[idx]
