'''
"Around here, however, we don't look backwards very long.  We keep
moving up new doors and doings, because we're curious...
and curiosity keeps leading us down new paths."  - Walt Disney

primary author: Christian Aaron Murga (aka the4960) - Owner of Greybox Security LLC
in collaboration with:

It is my hope this honeypot, as well as GreyBox Security, brings about
positive change and help protect many people, including those demographics
with less income.  I think blue-team focused software (like this tool)
does that with less ethical complication, and its nice to develop
something that.  Both types of software are indeed needed to improve
and advance the security landscape - its can become a grey area, but
its in our name.
'''

import argparse
from OsSpoofer import OsSpoofer
from ServiceSpoofer import ServiceSpoofer
from IDS import IDS
from SessionManager import SessionManager
from colorama import Fore, Back, Style
import sys
import time
import os


class OhHoney:
    description = "OhHoney is a python based honeypot designed to fool nmap -O -sV scans."
    path = ""

    def __init__(self, interface_list, os_id='', service_list='', ignore='', security_level=1,
                 log_dir=None, kill_file='', white_list='', black_list=''):
        if os_id == None:
            os_id = ''
        if service_list == None:
            service_list = ''
        if ignore == None:
            ignore = ''
        if log_dir == None:
            log_dir = os.path.dirname(sys.argv[0])+'/logs'
        if kill_file == None:
            kill_file = ''
        if security_level == None:
            security_level = 1
        if white_list == None:
            white_list = ''
        if black_list == None:
            black_list = ''
        self.interface_list = interface_list.split(',')
        self.os_id = os_id
        self.service_list = service_list
        self.services = self.service_list.split(';')
        self.ignore = ignore.split(',')
        self.kill_file = kill_file
        self.log_dir = log_dir
        self.security_level = int(security_level)
        self.white_list = white_list.split(',')
        self.black_list = black_list.split(',')
        # TODO V&V inputs

        if self.kill_file:
            w = open(self.kill_file + ".good", "w+")
            w.write("nothing gold can stay")
            w.close()

        if not self.interface_list[-1]:
            self.interface_list = self.interface_list[:-1]
        if not self.white_list[-1]:
            self.white_list = self.white_list[:-1]
        if not self.black_list[-1]:
            self.black_list = self.black_list[:-1]
        if not self.services[-1]:
            self.services = self.services[:-1]
        if not self.ignore[-1]:
            self.ignore = self.ignore[:-1]

        self.os_spoofer = None
        self.service_spoofer = None

        if self.security_level:
            self.ids = IDS(self.log_dir, self.security_level, self.white_list, self.black_list)
        #if self.os_id:
        self.os_spoofer = OsSpoofer(self.interface_list, self.os_id, self.ignore, self.services)
        if self.security_level:
            self.os_spoofer.addSubscriber(self.ids)
        print(str(self.os_spoofer))
        if self.service_list:
            self.service_spoofer = ServiceSpoofer(self.interface_list, self.services, self.os_spoofer)
            if self.security_level:
                self.service_spoofer.addSubscriber(self.ids)

        if self.os_spoofer:
            self.os_spoofer.start()
        if self.service_spoofer:
            self.service_spoofer.start()

        #'''
        # Normal mode
        while True if not self.kill_file else not os.path.isfile(self.kill_file):
            try:
                time.sleep(5)
            except:
                break
        if self.kill_file:
            os.remove(self.kill_file)
            os.remove(self.kill_file+".good")

        # '''

        '''
        # Testing mode
        time.sleep(5)
        OhHoney.scpNmap(self.os_spoofer, True, self.log_file)
        #time.sleep(3)
        #print('____________________FIRST ROUND DONE______________________')
        #OhHoney.scpNmap(self.os_spoofer, True, self.log_file)
        #time.sleep(3)
        #print('____________________SECOND ROUND DONE______________________')
        #OhHoney.scpNmap(self.os_spoofer, True)
        # '''

        if self.os_spoofer:
            self.os_spoofer.stop()
        if self.service_spoofer:
            self.service_spoofer.stop()
        if self.ids and not SessionManager.getInstance().is_android:
            self.ids.clearIptables()
        print('ALL DONE')

    @staticmethod
    def printArt():
        art = \
        r'''
              __________________________
             /                          \
            (                            )
            _@ssssssssssssssssssssssssss@_
          _/  @@@@sssssssssssssss@@@@@@@  \_
        _/        @@@@@@@@@@ssssss@@@       \_
       /                   @sssssss@          \
      /                     @@sssss@           \
     /                        @sss@             \
    |        Oh                @sss@             |
    |          Honey           @ss@              |
    |                           @ss@             |
     \                           @s@            /
      \                           @            /
       \_                                    _/
         \_                                _/ 
           \_                            _/
             \__________________________/
        '''
        color = {'s': Fore.LIGHTYELLOW_EX, '@': Fore.YELLOW, '.': Fore.YELLOW, ' ': '', '\n': ''}
        for letter in "\\_/|()":
            color[letter] = Fore.LIGHTRED_EX
        for letter in "OhHoney":
            color[letter] = Fore.YELLOW+Style.BRIGHT
        for letter in art:
            print(color[letter] + letter + Style.RESET_ALL, end="")
        print('')

    @staticmethod
    def scpNmap(spoofer, verbose, log=None):
        import os
        from SessionManager import Fingerprint
        # TODO get this to work w/ OS Spoofing (iptables)
        stamp = str(time.time())
        print('scpNmap start', stamp)
        #TODO generate namp command?
        requests = ['nmap 11.0.0.20 -vv -O -p 99,100 -sUT --max-os-tries 1 -oN /root/tests/results/stamp_' + stamp,
                    'sshpass -p toor scp /root/tests/results/stamp_' + stamp + ' 11.0.0.20:/root/tests/results/']
        w = open('/root/tests/requests/stamp-' + stamp, 'w')
        for request in requests:
            w.write(request + "\n")
        w.close()
        os.system("sshpass -p toor scp /root/tests/requests/stamp-" + stamp + " 11.0.0.10:/root/tests/requests/")

        # wait for results
        while not os.path.exists('/root/tests/results/stamp_' + stamp):
            time.sleep(1)
        if verbose:
            f = Fingerprint(scan_text=open('/root/tests/results/stamp_' + stamp, 'r').read())
            my_print = str(spoofer)
            actual_print = str(f)
            print('++++++++++++++++++++++ results are in! +++++++++++++++++++++++++++++++')
            print(my_print)
            print(spoofer.personality_fingerprint.name)
            print("********************************************************")
            print(actual_print)
            print("********************************************************")

            compare = spoofer.personality_fingerprint.compareFingerprint(f)
            if log:
                w = open(log, "w+")
                w.write(my_print+"\n")
                w.write("********************************************************\n")
                w.write(actual_print+"\n")
                w.write("********************************************************\n")
                w.write(compare+"\n")
                w.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=OhHoney.description)
    parser.add_argument('-o', metavar="os_id/name", help="operating system id or name to spoof. "
                                                         "If name is provided, it will find and use the first match. "
                                                         "ID is the index of the OS in the nmap OS db.")
    parser.add_argument('-s', metavar="service_list",
                        help="services to spoof. "
                             "Usage: -s [service] or [service];[service2];...\n"
                             "Service format: [port#],[tcp/udp],[id/name] "
                             "If name is provided, it will find and use the first match. "
                             "ID is the index of the service in the whitelisted services")
    parser.add_argument('-i', metavar="network_interface_list", help="network interface list"
                                                                     " Usage: [iface] or [iface],[iface2],...")
    parser.add_argument('-l', metavar="log_dir", help="directory to output logs to")
    parser.add_argument('-k', metavar="kill_file", help="when the file is created, the honeypot ends.")
    parser.add_argument('--ignore', metavar="ignored_ports",
                        help="ports the honeypot will not handle (usually those running a real service) "
                             "Usage: [port] or [port1],[port2],...")
    parser.add_argument('--level', metavar="security_level",
                        help="IDS security level. Default = 1.  "
                             "0: off, "
                             "1: log only, "
                             "2: low, "
                             "3: medium, "
                             "4: high")
    parser.add_argument('-w', metavar="whitelist_ips",
                        help="IP adresses for the honeypot to ignore. "
                             "Usage: [IP] or [IP1],[IP2],...")
    parser.add_argument('-b', metavar="blocklist_ips",
                        help="IP adresses for the honeypot to stop all connections to. "
                             "Usage: [IP] or [IP1],[IP2],...")
    # TODO
    # -c interactive console version
    # --config settings file (e.g. saved honeypot arguments)
    # -g GUI version
    # TODO check root permissions
    args = parser.parse_args()
    # TODO V&V args
    if not args.i:
        print("Please provide -i")
        sys.exit(0)
    if args.level:
        try:
            test = int(args.level)
            if test < 0 or test > 4:
                print('Please at provide an integer for --level (between 0-4)')
                sys.exit(0)
        except:
            print('Please at provide an integer for --level (between 0-4)')
            sys.exit(0)
        if args.level == 0 and not (args.o or args.s):
            print('OhHoney will do nothing in the config... shutting down.')
            sys.exit(0)
    OhHoney.printArt()
    OhHoney.path = sys.argv[0]
    honeypot = OhHoney(args.i, args.o, args.s, args.ignore, args.level, args.l, args.k, args.w, args.b)
    # self, interface_list, os_id='', service_list='', ignore='', security_level=1,
    #             log_dir='logs', kill_file='', white_list='', black_list=''):
