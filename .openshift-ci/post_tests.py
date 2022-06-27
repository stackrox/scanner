#!/usr/bin/env python3

"""
Common steps to run when e2e tests are complete. All post steps are run in spite
of prior failures. This models existing CI behavior from Circle CI.

Adapted from https://github.com/stackrox/stackrox/blob/master/.openshift-ci/post_tests.py
"""

import os
import subprocess
from typing import List


class PostTestsConstants:

    API_TIMEOUT = 5 * 60
    COLLECT_TIMEOUT = 5 * 60
    CHECK_TIMEOUT = 5 * 60
    STORE_TIMEOUT = 5 * 60
    FIXUP_TIMEOUT = 5 * 60

    K8S_LOG_DIR = "/tmp/k8s-service-logs"
    METRICS_DIR = "/tmp/metrics"
    STACKROX_LOG_DIR = "/tmp/stackrox-logs"


class NullPostTest:
    def run(self, test_output_dirs=None):
        pass


class RunWithBestEffortMixin:
    def __init__(
        self,
    ):
        self.exitstatus = 0
        self.failed_commands: List[List[str]] = []

    def run_with_best_effort(self, args: List[str], timeout: int):
        print(f"Running post command: {args}")
        runs_ok = False
        try:
            subprocess.run(
                args,
                check=True,
                timeout=timeout,
            )
            runs_ok = True
        except Exception as err:
            print(f"Exception raised in {args}, {err}")
            self.failed_commands.append(args)
            self.exitstatus = 1
        return runs_ok

    def handle_run_failure(self):
        if self.exitstatus != 0:
            for args in self.failed_commands:
                print(f"Post failure in: {args}")
            raise RuntimeError(f"Post failed: exit {self.exitstatus}")


class StoreArtifacts(RunWithBestEffortMixin):
    """For tests that only need to store artifacts"""

    def __init__(
        self,
        artifact_destination_prefix=None,
    ):
        super().__init__()
        self.artifact_destination_prefix = artifact_destination_prefix
        self.data_to_store = []

    def run(self, test_output_dirs=None):
        self.store_artifacts(test_output_dirs)
        self.handle_run_failure()

    def store_artifacts(self, test_output_dirs=None):
        if test_output_dirs is not None:
            self.data_to_store = test_output_dirs + self.data_to_store
        for source in self.data_to_store:
            args = ["scripts/ci/store-artifacts.sh", "store_artifacts", source]
            if self.artifact_destination_prefix:
                args.append(
                    os.path.join(
                        self.artifact_destination_prefix, os.path.basename(source)
                    )
                )
            self.run_with_best_effort(
                args,
                timeout=PostTestsConstants.STORE_TIMEOUT,
            )


# pylint: disable=too-many-instance-attributes
class PostClusterTest(StoreArtifacts):
    """The standard cluster test suite of debug gathering and analysis"""

    def __init__(
        self,
        check_stackrox_logs=False,
        artifact_destination_prefix=None,
    ):
        super().__init__(artifact_destination_prefix=artifact_destination_prefix)
        self._check_stackrox_logs = check_stackrox_logs
        self.k8s_namespaces = ["kube-system", "stackrox"]

    def run(self, test_output_dirs=None):
        self.collect_service_logs()
        self.collect_scanner_metrics()
        if self._check_stackrox_logs:
            self.check_stackrox_logs()
        self.store_artifacts(test_output_dirs)
        self.handle_run_failure()

    def collect_service_logs(self):
        for namespace in self.k8s_namespaces:
            self.run_with_best_effort(
                [
                    "scripts/ci/collect-service-logs.sh",
                    namespace,
                    PostTestsConstants.K8S_LOG_DIR,
                ],
                timeout=PostTestsConstants.COLLECT_TIMEOUT,
            )
        self.data_to_store.append(PostTestsConstants.K8S_LOG_DIR)

    def collect_scanner_metrics(self):
        self.run_with_best_effort(
            [
                "scripts/ci/collect-scanner-metrics.sh",
                "stackrox",
                PostTestsConstants.METRICS_DIR,
            ],
            timeout=PostTestsConstants.COLLECT_TIMEOUT,
        )
        self.data_to_store.append(PostTestsConstants.METRICS_DIR)

    def check_stackrox_logs(self):
        self.run_with_best_effort(
            [
                "scripts/ci/logcheck/check-logs.sh",
                "check_stackrox_logs",
                PostTestsConstants.K8S_LOG_DIR
            ],
            timeout=PostTestsConstants.CHECK_TIMEOUT,
        )


class FinalPost(StoreArtifacts):
    """Collect logs that accumulate over multiple tests and other final steps"""

    def __init__(
        self,
        artifact_destination_prefix="final",
    ):
        super().__init__(artifact_destination_prefix=artifact_destination_prefix)

    def run(self, test_output_dirs=None):
        self.store_artifacts()
        self.fixup_artifacts_content_type()
        self.make_artifacts_help()
        self.handle_run_failure()

    def fixup_artifacts_content_type(self):
        self.run_with_best_effort(
            ["scripts/ci/store-artifacts.sh", "fixup_artifacts_content_type"],
            timeout=PostTestsConstants.FIXUP_TIMEOUT,
        )

    def make_artifacts_help(self):
        self.run_with_best_effort(
            ["scripts/ci/store-artifacts.sh", "make_artifacts_help"],
            timeout=PostTestsConstants.FIXUP_TIMEOUT,
        )
