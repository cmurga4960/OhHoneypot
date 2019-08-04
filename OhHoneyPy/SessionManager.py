import random
from collections import Mapping
import socket
import fcntl
import struct
import os


# Singleton
class SessionManager:
    __instance = None

    @staticmethod
    def getInstance(fingerprint=None):
        """ Static access method. """
        if not SessionManager.__instance:
            SessionManager(fingerprint)
        return SessionManager.__instance

    def __init__(self, fingerprint):
        """ Virtually private constructor. """
        if SessionManager.__instance:
            raise Exception("This class is a singleton!")
        else:
            self.fingerprint = fingerprint
            self.ip_to_session = {}
            self.is_android = "android" in os.popen('uname -a').read().lower()
            SessionManager.__instance = self

    def getValue(self, ip, test, attribute, value=None):
        if ip not in self.ip_to_session:
            self.ip_to_session[ip] = Session(ip)
        return self.ip_to_session[ip].getValue(test, attribute, value)

    @staticmethod
    def getIpAddress(interface):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(), 0x8915, struct.pack('256s', bytes(interface[:15],'utf-8')))[20:24])


class Fingerprint(Mapping):
    NMAP_PATH = "OhHoneypot/OhHoneyPy/" if SessionManager.is_android else ''
    NMAP_FINGERPRINT_FILE = 'nmap-os-db'

    def __init__(self, fingerprint_id=-1, scan_text=""):
        self._storage = dict()

        self.name = ""
        self.classes = []
        self.cpes = []

        self.seq = {}
        self.seq_attribs = ['sp', 'gcd', 'isr', 'ti', 'ci', 'ii', 'ts', 'ts']
        self.ops = {}
        self.ops_attribs = ['o1', 'o2', 'o3', 'o4', 'o5', 'o6']
        self.win = {}
        self.win_attribs = ['w1', 'w2', 'w3', 'w4', 'w5', 'w6']
        self.ecn = {}
        self.ecn_attribs = ['r', 'df', 't', 'tg', 'w', 'o', 's', 'a', 'f', 'rd', 'cc', 'q']
        self.t1 = {}
        self.t2 = {}
        self.t3 = {}
        self.t4 = {}
        self.t5 = {}
        self.t6 = {}
        self.t7 = {}
        self.t_attribs = self.ecn_attribs
        self.u1 = {}
        self.u_attribs = ['df', 't', 'tg', 'ipl', 'un', 'ripl', 'rid', 'ripck', 'ruck', 'rud']
        self.ie = {}
        self.ie_attribs = ['dfi', 't', 'tg', 'cd']

        self.delimiter = "%"
        self.guess = False

        if scan_text:
            self.populateFromScan(scan_text)
        else:
            try:
                if int(fingerprint_id) >= 0:
                    self.populateFromNumber(int(fingerprint_id))
                else:
                    raise Exception("Provide fingerprint index or nmap scan results")
            except ValueError:
                if len(fingerprint_id):
                    self.populateFromString(fingerprint_id)
        if not self.name:
            raise Exception("Provide VALID fingerprint index/name or nmap scan results")

    # Tested for 0-6000
    def populateFromNumber(self, fingerprint_index):
        # There are 5652 fingerprints (as of now)
        db = open(Fingerprint.NMAP_PATH+Fingerprint.NMAP_FINGERPRINT_FILE, 'r')
        i = 0
        for line in db.read().split('\n'):
            if not line or line[0] == "#":
                continue
            if line.startswith("Fingerprint "):
                if self.name:
                    break
                if i == fingerprint_index:
                    self.name = line[12:]
                i += 1
            elif self.name:
                if line.startswith('Class '):
                    self.classes.append(line[6:])
                elif line.startswith('CPE '):
                    self.cpes.append(line[4:])
                else:
                    self._parseAttribute(line)


    def populateFromString(self, os_name):
        # There are 5652 fingerprints (as of now)
        db = open(Fingerprint.NMAP_PATH + Fingerprint.NMAP_FINGERPRINT_FILE, 'r')
        i = 0
        for line in db.read().split('\n'):
            if not line or line[0] == "#":
                continue
            if line.startswith("Fingerprint "):
                if self.name:
                    break
                if os_name.lower() in line.lower():
                    self.name = line[12:]
                i += 1
            elif self.name:
                if line.startswith('Class '):
                    self.classes.append(line[6:])
                elif line.startswith('CPE '):
                    self.cpes.append(line[4:])
                else:
                    self._parseAttribute(line)

    # Expects nmap scan with -vv and -O
    def populateFromScan(self, scan_text):
        wrapped_text = ""
        fingerprint_ready =False
        for line in scan_text.split("\n"):
            if not line:
                if fingerprint_ready:
                    break
                else:
                    continue
            if line.startswith("Running"):
                self.classes.append(line[line.index(":")+1:].strip())
            elif line.startswith("OS CPE"):
                self.cpes.append(line[line.index(":")+1:].strip())
            elif line.startswith("OS details"):
                self.name = line[line.index(":")+1:].strip()
            elif not self.name and line.startswith("Aggressive OS guesses:"):
                self.name = line[line.index(":")+1:].strip()
            elif not self.name and line.startswith("No exact OS matches for host"):
                self.name = "No exact matches"
            elif not self.name and line.startswith("No OS matches for host"):
                self.name = "No matches"
            elif not self.name and line.startswith("Too many fingerprints match this host to give specific OS details"):
                self.name = "Too many matches"
            elif line.startswith("OS:"):
                wrapped_text += line[3:].lower().strip()
            elif line.startswith("TCP/IP fingerprint"):
                fingerprint_ready = True
            elif "(" in line and ")" in line and ("=" in line or len(line) >= 4) and fingerprint_ready:  # needs testing
                if line.lower().startswith("scan("):
                    continue
                self._parseAttribute(line.lower().strip())
        if wrapped_text:
            for line in wrapped_text.split(")")[:-1]:
                if line and not line.startswith("scan("):
                    self._parseAttribute(line+")")

    def _parseAttribute(self, line):
        test = line[:line.index("(")].lower()
        data = line[line.index("(") + 1:-1].lower().split(self.delimiter)
        self[test] = {}
        # TODO is this safe? haha xD - trusting the nmap file
        e = "self." + test + " = self['"+test+"']"
        exec(e)
        for entry in data:
            try:
                key, value = entry.split("=")
                self[test][key] = value
            except:
                pass

    # Salamah and Servin, plz for give this terrible method T-T
    def compareFingerprint(self, fingerprint):
        same_value = ""
        diff_values = ""
        later_diff = ""
        for key in list(self):
            if key in list(fingerprint):
                my_value = self[key]
                there_value = fingerprint[key]
                if my_value == there_value:
                    # exact same test results for this test
                    same_value += "FingerAB:"+ key + "("
                    for entry in list(my_value):
                        value2 = my_value[entry]
                        same_value += entry + "=" + value2 + self.delimiter
                    same_value = same_value[:-1] + ")\n"
                else:
                    # both have test, but differ results (usual case)
                    same_value_index = len(same_value)
                    same_value += "FingerAB:" + key + "("
                    diff_a = "FingerA:" + key + "("
                    diff_b = "FingerB:" + key + "("
                    for my_entry in list(my_value):
                        my_value2 = my_value[my_entry]
                        if my_entry in list(there_value):
                            there_value2 = there_value[my_entry]
                            if my_value2 == there_value2:
                                same_value += my_entry + "=" + my_value2 + self.delimiter
                            else:
                                diff_a += my_entry + "=" + my_value2 + self.delimiter
                                diff_b += my_entry + "=" + there_value2 + self.delimiter
                        else:
                            diff_a += my_entry + "=" + my_value2 + self.delimiter  # value not in there test
                    for there_entry in list(there_value):
                        there_value2 = there_value[there_entry]
                        if there_entry not in list(my_value):
                            diff_b += there_entry + "=" + there_value2 + self.delimiter # value not in my test
                    if same_value[-1] == self.delimiter:
                        same_value = same_value[:-1]
                    if diff_a[-1] == self.delimiter:
                        diff_a = diff_a[:-1]
                    if diff_b[-1] == self.delimiter:
                        diff_b = diff_b[:-1]

                    # Handle no new same_values
                    if len(same_value) == same_value.rindex("(")+1:
                        same_value = same_value[:same_value_index]
                    else:
                        same_value += ")\n"
                    if diff_a == "FingerA:" + key + "(":
                        diff_a = ""
                    else:
                        diff_a += ")\n"
                    if diff_b == "FingerB:" + key + "(":
                        diff_b = ""
                    else:
                        diff_b += ")\n\n"
                    diff_values += diff_a + diff_b
            else:
                value = self[key]
                later_diff += "FingerA:" + key + "("
                for entry in list(value):
                    value2 = value[entry]
                    later_diff += entry+"="+value2+self.delimiter
                later_diff = later_diff[:-1]+")\n"
        diff_values += later_diff+"\n"
        for key in list(fingerprint):
            if key not in list(self):
                value = fingerprint[key]
                diff_values += "FingerB:" + key + "("
                for entry in list(value):
                    value2 = value[entry]
                    diff_values += entry + "=" + value2 + self.delimiter
                diff_values = diff_values[:-1] + ")\n"
        print("--- Same Values ---\n" + same_value)
        print("--- Diff Values ---\n" + diff_values)
        return "--- Same Values ---\n" + same_value + "--- Diff Values ---\n" + diff_values

    @staticmethod
    def doScan(conn):
        command = "nmap 11.0.0.20 -vv -O -p 90,91 -sUT --max-os-tries 1"
        in_std, out_std, err_std = conn.exec_command(command)
        scan_text = out_std.read().decode('utf-8')
        print("SSH SCAN\n", scan_text)
        return Fingerprint(scan_text=scan_text)

    def __str__(self):
        results = "Fingerprint: "+self.name + "\n"
        for i in range(len(self.classes)):
            results += "Class: "+self.classes[i] + "\n"
        for i in range(len(self.cpes)):
            results += "CPE: "+self.cpes[i] + "\n"
        for key in list(self):
            value = self[key]
            results += key+"("
            for entry in list(value):
                value2 = value[entry]
                results += entry+"="+value2+self.delimiter
            results = results[:-1]+")\n"
        return results[:-1]

    # Mapping/dict methods
    def __getitem__(self, key):
        return self._storage[key]

    def __setitem__(self, key, value):
        self._storage[key] = value

    def __iter__(self):
        return iter(self._storage)

    def __len__(self):
        return len(self._storage)


class Session:
    def __init__(self, ip):
        self.ip = ip
        self.tests = {}
        # self.tests[test][attribute] = [times_accessed, last_result]

    def getValue(self, test, attribute, value=None):
        count = 0
        if test not in self.tests:
            self.tests[test] = {}
            self.tests[test][attribute] = [count, 0]
        else:
            if attribute in self.tests[test]:
                count = self.tests[test][attribute][0]
            else:
                self.tests[test][attribute] = [count, 0]
        self.tests[test][attribute][0] += 1
        try:
            finger_val = SessionManager.getInstance().fingerprint[test][attribute]
        except:
            #print('Fingerprint didnt have value')
            finger_val = ")"  # an invalid value to show its not in fingerprint
        #print("Val in print:", finger_val)
        result = 0

        # lets do it to it
        # knock out simple ones first
        if "-" in finger_val:
            result,b = finger_val.split('-')
            #try:
            #    a = int(a,16)
            #    b = int(b,16)
            #    result = int((a+b)/2)
            #    result = str(bytes([result]))[4:-1]  # TODO pray this doesnt error haha - test
            #except:
            #    result = a  # count % 2
            return result
        if "|" in finger_val:
            result = finger_val.split('|')[0]
            if not(test == "seq" and (attribute == "ti" or attribute == "ci" or attribute == "ii")):
                return result
            else:
                #print(finger_val)
                finger_val = result
        if "z" == finger_val:
            return 0

        # then more complex
        if test == "seq" and (attribute == "ti" or attribute == "ci" or attribute == "ii"):
            # correlates to ip.id field range(0-65535 (or 0xFFFF))
            # random
            #print("///////////////////////////////")
            #print(attribute, finger_val)
            old_attribute = attribute
            #attribute = "ii"  # do this to better track id (instead of 3)
            if attribute not in self.tests[test]:
                self.tests[test][attribute] = [count, 0]
            if finger_val == 'rd':  # does not happen for ii due to sample size
                # need to increase by 20,000
                if count == 0:
                    result = random.randint(1, 400)
                elif count == 1 or count == 2:
                    result = self.tests[test][attribute][1] + 21000
                else:
                    result = random.randint(1, 60000)
            # random positive increments
            elif finger_val == 'ri':
                # add 1000 and not evenly divisible by 256
                # if is divisible by 256, must be > 256000
                if not count:
                    result = random.randint(1, 500)
                else:
                    result = self.tests[test][attribute][1] + random.randint(1001, 2000)
                if result/256 == int(result/256):
                    result += random.randint(1, 10)
            # broken increments
            elif finger_val == 'bi':
                # all differences divisible by 256 and no greater than 5120
                if not count:
                    result = random.randint(1, 100)
                else:
                    result = self.tests[test][attribute][1] + random.randint(1001, 2000)
                while not result/256 == int(result/256) and not result == 0:
                    result = (result+1) % 5120
            # incremental
            elif finger_val == 'i':
                # add from 1-10
                if not count:
                    result = random.randint(1, 20000)
                else:
                    result = self.tests[test][attribute][1] + random.randint(1, 8)
            elif not finger_val:
                # Value is ommited and does not match other rules...
                # Decrementing should not match... TODO test
                # This can be a legit desired outcome
                # - cant increase by 20,000 from start to finish
                if not count:
                    result = random.randint(10000, 11000)
                else:
                    #if count % 2 == 0:
                    #result = self.tests[test][attribute][1] - random.randint(11, 15)
                    #else:
                    result = self.tests[test][attribute][1] + random.randint(11, 20)
                if result <= 1 or result >= 65530:
                    result = random.randint(10000, 11000)
            else:
                # try hex value (ids are identical )
                try:
                    finger_val = int(finger_val, 16)
                    result = finger_val
                except:
                    pass

            attribute = old_attribute

        if test == "seq" and (attribute == "ss"):
            if finger_val == "s":
                if not count:
                    result = random.randint(1, 1000)
                else:
                    result = self.tests[test][attribute][1]+2  # TODO test
            else:  # ==o (other)
                # decrementing should work
                if not count:
                    result = random.randint(20000, 10000)
                else:
                    result = self.tests[test][attribute][1]-2  # TODO test

        #print(attribute, finger_val, result)
        self.tests[test][attribute][1] = result
        return result
