import requests

from bella.config import HALSEY_BASE_URL


class ApiWrapper(object):

    STATS = HALSEY_BASE_URL + "/sim/attack"
    QOS = HALSEY_BASE_URL + "/sim/qos"
    HIST = HALSEY_BASE_URL + "/ids/hist"
    VNET = HALSEY_BASE_URL + "/vnet/get?host="

    EVENTS_LIST = HALSEY_BASE_URL + "/v1/ids/events"
    ARP = HALSEY_BASE_URL + "/v1/topo/arp"
    SIMULATIONS_LIST = HALSEY_BASE_URL + "/v1/topo/sims"
    ALERTS_INFO = HALSEY_BASE_URL + "/v1/info/alerts"

    VNETS_TOGGLE = HALSEY_BASE_URL + "/vnet/toggle"
    VNETS_STATUS = HALSEY_BASE_URL + "/v1/vnet/status"
    VNETS_SET = HALSEY_BASE_URL + "/v1/vnet/set"
    VNETS_LIST = HALSEY_BASE_URL + "/v1/vnet/list"

    SIM_QOS_STATS = HALSEY_BASE_URL + "/v1/sim/qos"
    SIM_ATTACK_STATS = HALSEY_BASE_URL + "/v1/sim/attack"

    @classmethod
    def get_events(cls, interval=60):
        """
        :param interval: get events for last X seconds
        """
        return requests.get(cls.EVENTS_LIST, {"interval": interval}).json()

    @classmethod
    def get_arp_table(cls):
        return requests.get(cls.ARP).json()

    @classmethod
    def get_sims(cls):
        return requests.get(cls.SIMULATIONS_LIST).json()

    @classmethod
    def get_known_alert(cls):
        return requests.get(cls.ALERTS_INFO).json()

    @classmethod
    def vnet_list(cls):
        return requests.get(cls.VNETS_LIST).json()

    @classmethod
    def vnet_status(cls):
        return requests.get(cls.VNETS_STATUS).json()

    @classmethod
    def toggle(cls, mac):
        return requests.get(cls.VNETS_TOGGLE, {'host': mac}).json()

    @classmethod
    def set_vnet(cls, mac, vnet):
        return requests.get(cls.VNETS_SET, {'host': mac, 'vnet': vnet}).json()

    @classmethod
    def sim_qos_stats(cls):
        return requests.get(cls.SIM_QOS_STATS).json()

    @classmethod
    def sim_attack_stats(cls):
        return requests.get(cls.SIM_ATTACK_STATS).json()


