from scapy.all import sniff, IP, TCP
import time

class IntrusionDetector:
    def __init__(self):
        self.alert_threshold = 5
        self.alert_count = {}
        self.log_file = "intrusion_detection_log.txt"

    def packet_callback(self, packet):
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            dport = packet[TCP].dport

            
            if dport == 1337:
                self.log_intrusion(ip_src, dport)
                self.update_alert_count(ip_src)

                if self.alert_count[ip_src] >= self.alert_threshold:
                    self.alert("Possible intrusion from", ip_src)

    def update_alert_count(self, ip_src):
        self.alert_count[ip_src] = self.alert_count.get(ip_src, 0) + 1

    def alert(self, message, ip_src):
        print(f"{message} {ip_src}")
        self.send_email("Intrusion Detected", f"Possible intrusion from {ip_src}. Check your network.")

    def send_email(self, subject, body):
        pass

    def log_intrusion(self, ip_src, dport):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] Intrusion Detected - Source IP: {ip_src}, Destination Port: {dport}\n"

        with open(self.log_file, "a") as log_file:
            log_file.write(log_message)

detector = IntrusionDetector()

sniff(prn=detector.packet_callback, store=0)
