import re
from sys import argv, exit
from random import randint
from scapy.all import DNS, DNSQR, DNSRR, IP, sr1, UDP

RED = '\033[0;31m'
GREEN = '\033[0;32m'
CLOSE = '\033[0;m'


def handle_rcode(code):
    rc = {
        0 : f'{GREEN}NOERROR{CLOSE}',
        1 : f'{RED}FORMERR{CLOSE}',
        2 : f'{RED}SERVFAIL{CLOSE}',
        3 : f'{RED}NXDOMAIN{CLOSE}',
        4 : f'{RED}NOTIMP{CLOSE}',
        5 : f'{RED}REFUSED{CLOSE}',
        6 : f'{RED}NODATA{CLOSE}'
    }

    return f'{rc[code]}'
        

def return_pkt(packet: IP, answer: IP):
    dns_p = packet
    ans = answer

    src, dst = dns_p[0][IP].src, dns_p[0][IP].dst

    # **src <DNSAQUERY> dst :: qname found at addr -> host 

    # setup opts
    qname = str(ans[0][DNSQR].qname)
    host = ans[0][DNSRR].rdata

    # need to make loop to check if host is domain name (host points to another domain)
    if re.search('[a-zA-Z]', str(host)):
        print(f'STAT : GOT DOMAIN_DETECTED. DNSQR_QNAME=\"{qname}\" seems to point to RDATA within neighbor DNSRR as IPv4. DNSRR\'s may stack...\n')

    elif re.search('[0-9]', str(host)):
        print('GOT IPADDRESS_DOMAIN\n')

    # return
    print(f'\033[0;32m**\033[0;m{src} <DNSAQUERY@{dst}> :: {qname} found at IPv4 ADDR -> {host}')


# start
def main():
    dns_p = IP(dst="9.9.9.9")/UDP(sport=randint(1023, 65535), dport=53)/DNS(rd=1, qd=DNSQR(qname=str(argv[1])))
    ans = sr1(dns_p, verbose=0, iface='en1')

    print('++ Built DNS packet...')

    # need to get RCODE from reply from DNS server, client always assumes the name is correct
    rcode = ans[0][DNS].rcode
    host2a = ans[0][DNSQR].qname

    print(f'rcode={handle_rcode(rcode)}\nANSWER={ans}')

    supported_op = ['0', 0] # NOERROR
    
    # handle error codes
    error_op = [
        '1', 1, # FORMERR - Format error
        '2', 2, # SERVFAIL - Server fail
        '3', 3, # NXDOMAIN - Nonexistent domain
        '4', 4, # NOTIMP - Not implemented
        '5', 5, # REFUSED - Connection refused
        '6', 6  # NODATA - No data returned
    ]

    if rcode in supported_op:
        print(f'\nFound \"RCODE\" contained in supported_op :: RCODE=\033[0;32m{rcode}\033[0;m "ok"\n')
        
        # begin layer relay
        try:
            import time
            import datetime

            dt = datetime.datetime.now().timestamp()

        except (Exception, ImportError) as e_err:
            print(str(e_err))
            exit(1)
        
        else:
            print(f'STAT : Laying out layer fields and data | TS => {dt}\n\n',
            f'-=========================== Begin Emission Packet Display (BEPD) ===========================-')
            
            time.sleep(1)
            print(f'{str(ans[0].show())}\nHOST={host2a}')
            time.sleep(1)

            print(f'-=========================== End Emission Packet Display (EEPD) ===========================-')
            time.sleep(0.5)

        print(f'\n[\033[0;34m*\033[0;m] Printing Protocol Summary...\n{str(ans[0])}\n',
            f'\ntypeOf ans[0]={type(ans[0])}')

        return_pkt(dns_p, ans)

    elif rcode in error_op: # user input is not a domain name
        print('\033[0;31m** Failed to return server address. Try specifying a valid domain name.\033[0;m')
        exit(1)
        
        # end main

if __name__ == '__main__':
    main()
