#!/usr/bin/env python

import re
import yaml

from os.path import dirname, join
from logging import DEBUG


def _yml_conf():

    if hasattr(_yml_conf, "__cache__"):
        return getattr(_yml_conf, "__cache__")
    
    with open(join(dirname(__file__), "halsey.yml")) as f:
        res = yaml.load(f.read(), Loader=yaml.FullLoader)
        _yml_conf.__cache__ = res.copy()
        return res


def _get_vn(seclevel):
    return [vn for vn in VNETS if vn["security_level"] == seclevel][0]


VNETS = _yml_conf()["vnets"]

GATEWAY_DB_CONF = {
    vnet["name"]: {
        "MYSQL_DB_URL": vnet["gateway-ip"],
        "MYSQL_DB_USER": vnet.get("db_user", "snort"),
        "MYSQL_DB_PASS": vnet.get("db_pass", "snort"),
        "MYSQL_DB_NAME": vnet.get("db_name", "snort"),
    }
    for vnet in VNETS
}

GATEWAYS = [{"ip": n["gateway-ip"], "mac": n["gateway-mac"]} for n in
            (_get_vn(i) for i in range(1, len(VNETS) + 1))]

GCP_KEY_JSON = join(dirname(__file__), "key.json")

GEMEL_PATH = "/opt/gemel-sdn"

LOG_LEVEL = DEBUG


def BENIGN_LIST():
    return [h["internal_ip"] for h in _yml_conf()["simulations"]["benign"]]


def MALICIOUS_LIST():
    return [h["internal_ip"] for h in _yml_conf()["simulations"]["malicious"]]


PORT = _yml_conf()["port"]

SIMULATIONS = _yml_conf()["simulations"]

ALERTS = _yml_conf()["alerts"]
