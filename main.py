""" 
Developed by AVCDO
> Do not use this script for malicious purposes!
"""

import argparse
from platform import system
from math import trunc
from socket import socket, AF_INET, SOCK_RAW, IPPROTO_ICMP
from threading import Thread

MAX = 256
PACKET = b'\x08\x00\xf7\xff\x00\x00\x00\x00'

class colors:
    def __init__(self) -> None:
        if self.__check_sys():
            self.__fix_colors_windows()

        self.RESET = '\033[0m'
        self.BOLD = '\033[01m'
        self.RED = '\033[31m'
        self.GREEN = '\033[32m'
        self.ORANGE = '\033[33m' # not used
        self.BLUE = '\033[34m' # not used
        self.CYAN = '\033[36m'
    
    def __fix_colors_windows(self) -> None:
        """Fixing colors for windows."""
        kernel32 = __import__('ctypes').WinDLL('kernel32')
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        del kernel32
    
    def __check_sys(self) -> bool:
        """Check for system."""
        ops = system()
        if ops == 'Windows': del ops; return True
        elif ops == 'Linux': del ops; return False
        else: del ops; return None

color = colors()

def handle_args() -> dict:
    """Get parsed args as dictionary."""
    args = {}
    default = (None, 30, 1, 1)
    p = argparse.ArgumentParser(
        prog='pingsweep',
        description='Pingsweep some IP\'s, but don\'t use it for illegal purposes.',
        epilog='Developed by AVCDO'
    )
    p.add_argument('target')
    p.add_argument('-r', '--scan_range')
    p.add_argument('-c', '--count_threads')
    p.add_argument('-j', '--jumps')

    for idx, arg in enumerate(p.parse_args()._get_kwargs()): # convert kwargs to dict
        args.update({arg[0]: arg[1] if arg[1] is not None else default[idx]})
    return args

def ping(addr:str) -> object:
    """Send ICMP echo request packet to the address and recieve a reply packet if host is reachable."""
    try:
        with socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) as server:
            server.bind(("0.0.0.0", 0))
            server.settimeout(3)
            server.sendto(PACKET, (addr, 0))
            server.recvfrom(1024)
        return True
    except WindowsError: 
        return False

def calc_addr(target:str, scan_r:int, jumps:int) -> object:
    for i in range(0, scan_r+1, jumps): # update address
        addr = list(map(int, target.split('.')))
        addr.reverse()
        # extrapolate address
        div = trunc((addr[0]+i)/MAX)
        div2 = trunc((addr[1]+div)/MAX)
        addr[0] += i-MAX*div
        addr[1] += div-MAX*div2
        addr[2] += div2
        if addr[2] > MAX: # check if limit was reached
            raise ValueError('IP reached range limit')
        addr.reverse() # format addr
        addr = '.'.join(map(str, addr))
        yield addr

def scan(targets:tuple) -> None:
    """Check if addresses are reachable."""
    for addr in targets:
        if ping(addr): print(f'[{color.CYAN}{addr}{color.RESET}] --> {color.GREEN}{color.BOLD}reachable{color.RESET}')
        else: print(f'[{color.CYAN}{addr}{color.RESET}] --> {color.RED}{color.BOLD}unreachable{color.RESET}')

def main() -> None:
    """Manage inputs and split up threads."""
    args = handle_args()
    scan_r = trunc(int(args.get('scan_range'))/int(args.get('count_threads')))
    target = args.get('target')

    for _ in range(int(args.get('count_threads'))):
        targets = tuple(calc_addr(target, scan_r, int(args.get('jumps')))) # generate targets
        Thread(target=scan, args=(targets, )).start()
        target = targets[-1] # update target for calculation


if __name__ == '__main__':
    main()
