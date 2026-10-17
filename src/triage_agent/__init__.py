"""TrustSight triage agent.

Polls the TrustSight feed for ``trustsight.alerts`` events, enqueues one job
per over-threshold (package, version transition), and drives each job to a
verified verdict plus, where warranted, a fix PR or a confirmed-IOC alert.

The heavy lifting (verdict verification, PR generation, alert publication)
is delegated to the ``harness`` CLI from trustsight-harness, which is
installed in the job image. This package does not import the harness.
"""

__version__ = "0.1.0"
