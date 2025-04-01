import json

from json import JSONDecodeError

from gemel.config import ODL_VTN_API_URL, ODL_MAIN_API_URL
from requests import get, post
from requests.auth import HTTPBasicAuth


def _odl_params():
    return {
        "auth": HTTPBasicAuth("admin", "admin"),
        "headers": {
            "Content-type": "application/json"
        }
    }


def vtn_api_get(path, params=None):
    r = get(ODL_VTN_API_URL + path, params=params, **_odl_params())
    r.raise_for_status()
    return r.json()


def vtn_api_post(path, data=None):
    r = post(ODL_VTN_API_URL + path, data=json.dumps(data), **_odl_params())
    r.raise_for_status()
    try:
        return r.json()
    except JSONDecodeError:
        return r.text


def odl_api_get(path, params=None):
    r = get(ODL_MAIN_API_URL + path, params=params, **_odl_params())
    r.raise_for_status()
    return r.json()


def odl_api_post(path, data=None):
    r = post(ODL_MAIN_API_URL + path, data=json.dumps(data), **_odl_params())
    r.raise_for_status()
    return r.json()


if __name__ == "__main__":
    import json
    topology = odl_api_get("/network-topology:network-topology/")
    print(json.dumps(topology, indent=2))


