#!/usr/bin/env python3

"""
Available tests

Adapted from https://github.com/stackrox/stackrox/blob/master/.openshift-ci/ci_tests.py
"""

import subprocess

from common import popen_graceful_kill


class BaseTest:
    def __init__(self):
        self.test_output_dirs = []

    def run_with_graceful_kill(self, args, timeout, post_start_hook=None):
        with subprocess.Popen(args) as cmd:
            if post_start_hook is not None:
                post_start_hook()
            try:
                exitstatus = cmd.wait(timeout)
                if exitstatus != 0:
                    raise RuntimeError(f"Test failed: exit {exitstatus}")
            except subprocess.TimeoutExpired as err:
                popen_graceful_kill(cmd)
                raise err


class NullTest(BaseTest):
    def run(self):
        pass


class E2ETest(BaseTest):
    TEST_TIMEOUT = 60 * 60

    def run(self):
        print("Executing E2E tests")

        self.run_with_graceful_kill(
            ["scripts/ci/e2e-tests.sh"],
            E2ETest.TEST_TIMEOUT,
        )
