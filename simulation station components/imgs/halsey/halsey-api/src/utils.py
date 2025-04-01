
import subprocess
import logging


def bash(command):
    return subprocess.check_output(["bash", "-c", command])


def get_logger(name):
    import config
    logging.basicConfig(level=config.LOG_LEVEL, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(name)
    return logger


default_logger = get_logger("Halsey")


def logd(*args):
    default_logger.debug(*args)


def logi(*args):
    default_logger.info(*args)


def loge(*args):
    default_logger.error(*args)


