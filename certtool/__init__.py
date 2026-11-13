"""certtool - automated SSL certificate exchange for SAP Commerce Cloud (CCv2).

Wraps the SAP Commerce Cloud Management CLI (sapccm) to
  * upload certificates kept in this repository to the subscription,
  * roll them out to the endpoints of a single environment,
  * clean up certificates that are no longer needed.
"""

__version__ = "0.1.0"
