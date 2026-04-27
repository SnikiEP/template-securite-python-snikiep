from scapy.all import sniff, ARP, IP, TCP, Raw

from src.tp1.utils.config import logger
from src.tp1.utils.lib import choose_interface


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.summary = ""
        self.packets = []
        self.protocols = {}

    def capture_traffic(self) -> None:
        logger.info(f"Capture traffic from interface {self.interface}")
        self.packets = sniff(iface=self.interface, count=100, timeout=30)

    def sort_network_protocols(self) -> str:
        sorted_p = sorted(self.protocols.items(), key=lambda x: x[1], reverse=True)
        return str(sorted_p)

    def get_all_protocols(self) -> str:
        self.protocols = {}
        for pkt in self.packets:
            for layer in pkt.layers():
                name = layer.__name__
                self.protocols[name] = self.protocols.get(name, 0) + 1
        return str(self.protocols)

    def analyse(self, protocols: str) -> None:
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        logger.debug(f"All protocols: {all_protocols}")
        logger.debug(f"Sorted protocols: {sort}")
        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        return self.summary

    def _gen_summary(self) -> str:
        alerts = []
        arp_table = {}

        for pkt in self.packets:
            if pkt.haslayer(ARP) and pkt[ARP].op == 2:
                ip = pkt[ARP].psrc
                mac = pkt[ARP].hwsrc
                if ip in arp_table and arp_table[ip] != mac:
                    alerts.append(f"[ALERT] ARP Spoofing: {ip} claimed by {mac} (was {arp_table[ip]})")
                else:
                    arp_table[ip] = mac

            if pkt.haslayer(Raw) and pkt.haslayer(TCP):
                payload = pkt[Raw].load.decode("utf-8", errors="ignore").lower()
                sql_keywords = ["select ", "union ", "' or ", "' and ", "drop ", "insert "]
                for kw in sql_keywords:
                    if kw in payload:
                        src = pkt[IP].src if pkt.haslayer(IP) else "unknown"
                        alerts.append(f"[ALERT] SQL Injection from {src}: {payload[:100]}")
                        break

        if not alerts:
            return "All traffic looks legitimate."
        return "\n".join(alerts)
