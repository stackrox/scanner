#!/usr/bin/env -S python3 -u

"""
Run E2E tests in a GKE cluster
"""
import os
from pre_tests import PreSystemTests
from ci_tests import E2ETest
from post_tests import PostClusterTest, CheckStackroxLogs, FinalPost
from clusters import GKECluster
from runners import ClusterTestSetsRunner

# set required test parameters
os.environ["ORCHESTRATOR_FLAVOR"] = "k8s"

# override default test environment
os.environ["LOAD_BALANCER"] = "lb"

ClusterTestSetsRunner(
    cluster=GKECluster("e2e-tests"),
    sets=[
        {
            "name": "E2E tests",
            "pre_test": PreSystemTests(),
            "test": E2ETest(),
            "post_test": PostClusterTest(
                check_stackrox_logs=True,
                artifact_destination_prefix="e2e-tests",
            ),
        },
    ],
    final_post=FinalPost(
        store_qa_test_debug_logs=True,
    ),
).run()
