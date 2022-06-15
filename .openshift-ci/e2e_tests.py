#!/usr/bin/env -S python3 -u

"""
Run E2E tests in a GKE cluster
"""
import os
from pre_tests import PreE2ETests
from ci_tests import E2ETest
from post_tests import PostClusterTest, CheckStackroxLogs, FinalPost
from clusters import GKECluster
from runners import ClusterTestRunner

# set required test parameters
os.environ["ORCHESTRATOR_FLAVOR"] = "k8s"

# override default test environment
os.environ["LOAD_BALANCER"] = "lb"

ClusterTestRunner(
    cluster=GKECluster("e2e-tests"),
    pre_test=PreE2ETests(),
    test=E2ETest(),
    post_test=PostClusterTest(
        check_stackrox_logs=True,
        artifact_destination_prefix="e2e-tests",
    ),
    final_post=FinalPost(),
).run()
