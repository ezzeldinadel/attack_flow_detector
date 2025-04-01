import re

from subprocess import check_output, CalledProcessError
from gemel.vnet import vtn


HOST_IMAGES = ["mg-host-base", "mg-benign-googler", "mg-malish-apt"]
GW_IMAGES = ["mg-ids", "mg-ips"]


def _log(msg):
    print(msg)


def _bash(cmd):
    return check_output(["bash", "-c", "%s" % cmd]).decode('utf-8')


def list_conts(image_name=None):
    ps = [l for l in _bash("docker ps").split("\n") if l][1:]
    if image_name:
        ps = [x for x in ps if image_name in x]
    res = [x.group(1) for x in [re.match(r".*(mn.*).*", l) for l in ps] if x]
    return res


def get_mac_of(contname):
    res =  _bash("""
docker exec -it %s bash -c 'ifconfig $(cat /etc/hostname)-eth0 | grep -oE "HWaddr .*" | cut -d" " -f 2'
            """ % contname)
    return res.strip()


def send_ping(cname):
    try:
        _bash(""" docker exec -it {} ping -c1 -W1 210.0.0.1 """.format(cname))
    except CalledProcessError as e:
        pass


def install_vns():
    vtn.setup_vtn("vnet1", "vbr1")
    vtn.setup_vtn("vnet2", "vbr2")


def init_vns(introduce=True):

    _log("send pings")
    if introduce:
        for cont in list_conts():
            send_ping(cont)

    _log("adding hosts to vnet1")
    for himage in HOST_IMAGES:
        _log("adding host: " + himage)
        for hname in list_conts(himage):
            vtn.reassign_vtn(get_mac_of(hname), "vnet1", safe=True)

    _log("adding gatewys to their vnet")
    for gwimage in GW_IMAGES:
        for gwname in list_conts(gwimage):
            _log("adding gw: " + gwname)
            gw_number = re.match(r".*(\d+).*", gwname).group(1)
            vtn.reassign_vtn(get_mac_of(gwname), "vnet%s" % gw_number, safe=True)


