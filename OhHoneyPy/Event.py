import enum


class Event:
    def __init__(self, event_type, data):
        self.event_type = EventTypes.enumToString(event_type)
        self.data = data
        self.weight = 0
        if event_type == EventTypes.GenericNmapScan:
            self.weight = 1
        elif event_type == EventTypes.ServiceVersionScan:
            self.weight = 2
        elif event_type == EventTypes.OSScan:
            self.weight = 2
        elif event_type == EventTypes.UDPScan:
            self.weight = 2
        elif event_type == EventTypes.TCPScan:
            self.weight = 1
        elif event_type == EventTypes.ICMPScan:
            self.weight = 1
        elif event_type == EventTypes.UDPHit:
            self.weight = 1
        elif event_type == EventTypes.TCPHit:
            self.weight = 1
        elif event_type == EventTypes.ICMPHit:
            self.weight = 1
        else:
            self.weight = 0

    def __str__(self):
        return self.event_type + ": " + self.data


class EventTypes(enum.Enum):
    GenericNmapScan = 1
    ServiceVersionScan = 2
    OSScan = 3
    UDPScan = 4
    TCPScan = 5
    ICMPScan = 6
    UDPHit = 7
    TCPHit = 8
    ICMPHit = 9

    @staticmethod
    def enumToString(event_type):
        if event_type == EventTypes.GenericNmapScan:
            return "GenericNmapScan"
        elif event_type == EventTypes.ServiceVersionScan:
            return "ServiceVersionScan"
        elif event_type == EventTypes.OSScan:
            return "OSScan"
        elif event_type == EventTypes.UDPScan:
            return "UDPScan"
        elif event_type == EventTypes.TCPScan:
            return "TCPScan"
        elif event_type == EventTypes.ICMPScan:
            return "ICMPScan"
        elif event_type == EventTypes.UDPHit:
            return "UDPHit"
        elif event_type == EventTypes.TCPHit:
            return "TCPHit"
        elif event_type == EventTypes.ICMPHit:
            return "ICMPHit"
        else:
            return "???"
