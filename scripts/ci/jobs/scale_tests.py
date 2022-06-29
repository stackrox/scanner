#!/usr/bin/env -S python3 -u

"""
Run E2E tests in a GKE cluster
"""
from pre_tests import PreE2ETests
from ci_tests import ScaleTest
from post_tests import PostClusterTest, FinalPost
from clusters import GKECluster
from runners import ClusterTestRunner

ClusterTestRunner(
    cluster=GKECluster("scale-tests"),
    pre_test=PreE2ETests(),
    test=ScaleTest(),
    post_test=PostClusterTest(
        check_stackrox_logs=True,
        artifact_destination_prefix="scale-tests",
    ),
    final_post=FinalPost(),
).run()
