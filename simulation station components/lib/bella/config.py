
import yaml
from os import path
from os.path import dirname


def _get_yaml_conf():
    """
    Load YAML config file as python dict
    """
    if hasattr(_get_yaml_conf, "CACHE"):
        return _get_yaml_conf.CACHE

    yml_path = path.join(dirname(__file__), "config.yml")

    with open(yml_path) as f:
        _get_yaml_conf.CACHE = yaml.load(f.read(), Loader=yaml.FullLoader)

    return _get_yaml_conf.CACHE


HALSEY_BASE_URL = _get_yaml_conf()["base-url"]

MAX_ALERTS_PER_HOST = _get_yaml_conf()["max-alerts-per-host"]

MAX_STEPS_PER_EPISODE = _get_yaml_conf()["max-steps-per-episode"]

