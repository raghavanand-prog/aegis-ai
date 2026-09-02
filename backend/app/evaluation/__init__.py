"""Detection evaluation.

Measures the deterministic V1/V2 detection engine against a labelled dataset
with explicit ground truth. There is no model here and nothing is learned: this
package exists to establish an honest baseline before any ML work begins.

    dataset (labelled)  ->  normalizer  ->  detection engine  ->  metrics  ->  report

Run it with::

    python -m app.evaluation.run_detection_eval
"""

from app.evaluation.labels import MALICIOUS_LABELS, Label

__all__ = ["Label", "MALICIOUS_LABELS"]
