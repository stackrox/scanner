from datetime import datetime
import subprocess

'''
Adapted from https://github.com/stackrox/stackrox/blob/master/.openshift-ci/common.py
'''

def popen_graceful_kill(cmd):
    log_print(f"Sending SIGTERM to {cmd.args}")
    cmd.terminate()
    try:
        cmd.wait(5)
        log_print("Terminated")
    except subprocess.TimeoutExpired as err:
        log_print(f"Exception raised waiting after SIGTERM to {cmd.args}, {err}")
        # SIGKILL if necessary
        log_print(f"Sending SIGKILL to {cmd.args}")
        cmd.kill()
        cmd.wait(5)
        log_print("Terminated")

def log_print(*args):
    now = datetime.now()
    time = now.strftime("%H:%M:%S")
    print(f"{time}:", *args)
