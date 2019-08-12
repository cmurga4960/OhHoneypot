import enum


class Event:
    # TODO experiment with
    scale_difference = 100

    def __init__(self, event_type, data):
        self.event_type = event_type.name
        self.data = data
        self.weight = int(event_type.value)
        # 1 = low, could be normal
        # 2 = med, standard nmap (could just be looking)
        # 3 = high, non standard nmap command

    def __str__(self):
        return self.event_type + ": " + self.data


class EventTypes(enum.Enum):
    #__order__ = "GenericNmapScan ServiceVersionScan OSScan UDPScan TCPScan ICMPScan UDPHit TCPHit ICMPHit"
    # A scan is a packet unique to nmap - can be on an open or closed port
    # This shows clear intent
    # GenericNmapScan = 2.1
    ServiceVersionScanTCP = 3.1
    ServiceVersionScanUDP = 3.11  # This makes a ton of noise... maybe upgrade to 4
    OSScan = 3.2
    UDPScan = 3.3
    TCPScan = 2.2
    ICMPScan = 3.4
    # A hit is a normal request and on any port
    # This many include normal traffic from the user (ideally ignored in later versions w/ better sniffing and iptables)
    UDPHit = 1.1
    TCPHit = 1.2
    ICMPHit = 1.3
    # A normal request to an open ServiceSpoofer port - should not normally happen
    # Likely either a hacker trying to start an attack or some software probing for a server (e.g video game lan party)
    UDPOpenHit = 2.1
    TCPOpenHit = 2.2


    # @staticmethod
    # def enumToString(event_type):
    #     if event_type == EventTypes.GenericNmapScan:
    #         return "GenericNmapScan"
    #     elif event_type == EventTypes.ServiceVersionScan:
    #         return "ServiceVersionScan"
    #     elif event_type == EventTypes.OSScan:
    #         return "OSScan"
    #     elif event_type == EventTypes.UDPScan:
    #         return "UDPScan"
    #     elif event_type == EventTypes.TCPScan:
    #         return "TCPScan"
    #     elif event_type == EventTypes.ICMPScan:
    #         return "ICMPScan"
    #     elif event_type == EventTypes.UDPHit:
    #         return "UDPHit"
    #     elif event_type == EventTypes.TCPHit:
    #         return "TCPHit"
    #     elif event_type == EventTypes.ICMPHit:
    #         return "ICMPHit"
    #     else:
    #         return "???"
