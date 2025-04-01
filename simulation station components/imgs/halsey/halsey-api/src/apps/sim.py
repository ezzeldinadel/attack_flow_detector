import requests

from config import BENIGN_LIST, MALICIOUS_LIST, SIMULATIONS


def get_hosts_qos__legacy():
    """
    Collects QoS metric values from the hosts running the legacy
    ping RTT script
    """

    def _get_qos_info__legacy(ip, path):
        return requests.get("http://%s:8000/%s" % (ip, path)).text.strip()

    # receives insight lists for a IP group
    def ip_list(ips):
        return [{
            "mac": _get_qos_info__legacy(ip, "mac.txt"),
            "host": _get_qos_info__legacy(ip, "hostname.txt"),
            "insight": _get_qos_info__legacy(ip, "insight.txt"),
            "google-ip": ip
        } for ip in ips]

    return {
        "benign": ip_list(BENIGN_LIST()),
        "malicious": ip_list(MALICIOUS_LIST())
    }


def get_hosts_qos():
    _get = lambda ip: requests.get("http://%s:8000/benign.res.json" % ip).json()
    return [{**_get(h["internal_ip"]), "host": h} for h in SIMULATIONS["benign"]]


def get_attack_stats():
    # gets a file using HTTP request
    get = lambda ip, f: requests.get("http://%s:8001/%s" % (ip, f)).text.strip()
    ls = [{
        "stats": get(ip, "attack-stats.json"),
        # "mac": get(ip, "mac.txt"),
        # "host": get(ip, "hostname.txt"),
        "google-ip": ip
    } for ip in MALICIOUS_LIST()]
    return ls


