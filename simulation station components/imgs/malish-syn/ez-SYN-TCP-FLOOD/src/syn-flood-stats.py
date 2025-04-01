"""Naval Fate.

Usage:
  syn-flood-stats.py <ip> <port>
  syn-flood-stats.py (-h | --help)

Options:
  -h --help     Show this screen.

"""

import os
import signal
import logging
import threading
import time
import json
import sys
from docopt import docopt

from scapy.all import *

FORMAT = '%(asctime)s - %(name)s %(levelname)s - %(message)s'
logging.basicConfig(format=FORMAT)

logger = logging.getLogger("SYN-flood-stats")
logger.setLevel(logging.INFO)


EXIT_SIGNAL = False


class Context(object):
    """
    Data class for storing the stats
    """

    def __init__(self):
        self.syn_count = 0
        self.ack_count = 0
        self.total_syn_count = 0
        self.total_ack_count = 0
        self.syn_lock = threading.Lock()
        self.ack_lock = threading.Lock()


def _on_syn_sent(ctx):
    """
    SYN callback
    """
    def _res(pkt):
        logger.debug("syn sent %s", pkt.summary().strip())
        ctx.total_syn_count += 1
        with ctx.syn_lock:
            ctx.syn_count += 1

    return _res


def _on_ack_rcvd(ctx):
    """
    ACK callback
    """
    def _res(pkt):
        logger.debug("ack received %s", pkt.summary().strip())
        ctx.total_ack_count += 1
        with ctx.ack_lock:
            ctx.ack_count += 1

    return _res


def _sniff(filter_str, callback):

    logger.info(f"Sniff launched for filter: {filter_str}")

    while not EXIT_SIGNAL:
        sniff(filter=filter_str, prn=callback, timeout=2)

    logger.info(f"Sniff finished for filter: {filter_str}")


def _writer_thread(interval, ctx):

    serve_dir = os.environ.get("SERVE_DIR", os.path.dirname(__file__))
    out_path = os.path.join(serve_dir, "attack-stats.json")

    while not EXIT_SIGNAL:

        time.sleep(interval)

        logger.info(f"writing stats to file (syn={ctx.total_syn_count} ack={ctx.total_ack_count})")

        with open(out_path, "w") as f, ctx.ack_lock, ctx.syn_lock:
            f.write(json.dumps({
                "ratio": (ctx.ack_count / ctx.syn_count) \
                        if ctx.syn_count != 0 else 0,
                "total-ratio": (ctx.total_ack_count / ctx.total_syn_count) \
                        if ctx.total_syn_count != 0 else 0,
            }))
            ctx.ack_count = 0
            ctx.syn_count = 0

    logger.info("writer thread return")



def _launch(dst, dst_port):

    global EXIT_SIGNAL

    ctx = Context()

    threads = [
        # syns sent
        threading.Thread(target=_sniff, args=(f"dst {dst} and port {dst_port} and tcp[13] & 2 != 0", _on_syn_sent(ctx))),
        # acks received
        threading.Thread(target=_sniff, args=(f"src {dst} and port {dst_port} and tcp[13] & 16 != 0", _on_ack_rcvd(ctx))),
        # file report
        threading.Thread(target=_writer_thread, args=(3, ctx))
    ]

    for t in threads:
        t.start()

    while True:

        try:
            for t in threads:
                t.join()
            break
        except KeyboardInterrupt:

            if EXIT_SIGNAL:
                os.kill(os.getpid(), signal.SIGKILL)

            EXIT_SIGNAL = True
            logger.info("Quit signal received...")

    logger.info("Finished")


if __name__ == '__main__':
    arguments = docopt(__doc__)
    _launch(arguments["<ip>"], arguments["<port>"])


