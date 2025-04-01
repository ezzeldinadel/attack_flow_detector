
from subprocess import check_output
from os import environ


def bash_run(cmd):
    escaped_cmd = cmd.replace("'", r"\'")
    return check_output(["bash", "-c", "%s" % escaped_cmd], env=environ)


