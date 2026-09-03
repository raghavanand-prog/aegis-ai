"""Distribution drift detection.

Drift detection here produces a **signal**, never an action. Nothing in this
package retrains, rescores or changes a threshold; it reports that the world
looks different from the window a model was fitted on, and leaves what to do
about that to an analyst.
"""
