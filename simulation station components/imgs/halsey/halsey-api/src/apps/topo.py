
from gemel.vnet import vtn
from config import GATEWAYS, SIMULATIONS


def get_arp_table():

    topology = vtn.get_topology()
    nodes = topology["network-topology"]["topology"][0]["node"]
    arp_table = {}

    for n in nodes:

        if "host-tracker-service:addresses" not in n:
            continue

        for addr in n["host-tracker-service:addresses"]:
            if addr["mac"] in (gw["mac"] for gw in GATEWAYS):
                continue
            arp_table[addr["ip"]] = arp_table.get(addr["ip"], []) + [addr["mac"]]

    return arp_table


def get_sims():
    return SIMULATIONS


if __name__ == "__main__":
    get_arp_table()

