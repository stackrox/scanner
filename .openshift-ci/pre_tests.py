"""
PreTests - something to run before test but after resource provisioning.

Adapted from https://github.com/stackrox/stackrox/blob/master/.openshift-ci/pre_tests.py
"""

import subprocess


class Deployer:
    """
    Deployer - Deploys Scanner and ScannerDB resources and port-forwards the necessary endpoints.
    """

    DEPLOY_TIMEOUT = 41 * 60

    def __init__(self, slim=False):
        self.slim = slim

    def run(self):
        cmd = "deploy"
        if self.slim:
            cmd = "slim-deploy"
        subprocess.run(
            [
                "scripts/ci/deploy.sh",
                cmd
            ],
            check=True,
            timeout=Deployer.DEPLOY_TIMEOUT
        )


class NullPreTest:
    def run(self):
        pass


class PreSystemTests:
    """
    PreSystemTests - System tests need images.
    """

    # Poll for 2 hours.
    POLL_TIMEOUT = 120 * 60

    def run(self):
        self.poll_for_images()

    def poll_for_images(self):
        subprocess.run(
            [
                "scripts/ci/lib.sh",
                "poll_for_system_test_images",
                str(PreSystemTests.POLL_TIMEOUT),
            ],
            check=True,
            timeout=PreSystemTests.POLL_TIMEOUT * 1.2,
        )


class PreE2ETests(PreSystemTests):
    """
    PreE2ETests - Ensure all resources are ready for E2E tests to run properly.
    """

    def __init__(self, slim=False):
        self.slim = slim

    def run(self):
        super().run()
        Deployer(self.slim).run()
