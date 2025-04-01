#!/usr/bin/env python3

from utils import bash, logi
from config import GCP_KEY_JSON, GEMEL_PATH, SIMULATIONS
from filepath.filepath import fp

from gemel.vnet import vtn as vnmanager

import json


def move_host_to_vn(mac, vtn):
    # vnmanager.reassign_vtn(mac, vtn, safe=True)
    # return {"status": "OK"}
    return move_host_to(mac, vtn)


def get_vn(host_mac):
    res = vnmanager.get_current_interface(host_mac)
    return {"net": res[0] if res else "None"}


def toggle_vn(host_mac):
    vnmanager.toggle_vtn(host_mac)
    return {"status": "OK"}


def move_host_to(mac, vnet):
    import time
    counter = 0

    target_status = status()
    target_status[mac] = vnet

    current_status = status()

    while target_status != current_status:
        counter += 1
        print("### set {} to {}, pass: {}".format(mac, vnet, counter))
        print(target_status)
        print(current_status)
        for hmac, target in target_status.items():
            if target != current_status[hmac]:
                vnmanager.reassign_vtn(hmac, target, safe=True)
            current_status = status()

    # while current_int is None or current_int[0] != vnet:
    #     print("Update %s to %s, retry %d" % (mac, vnet, counter))
    #     vnmanager.reassign_vtn(mac, vnet, safe=True)
    #     time.sleep(1)
    #     counter += 1
    #     current_int = vnmanager.get_current_interface(mac)
    # # vnmanager.reassign_vtn(host_mac, vnet_name, safe=True)
    return {"status": "OK"}


def status():
    return {host["mac"]: get_vn(host["mac"])["net"] for _, hosts in SIMULATIONS.items() for host in hosts}

