"""Controlled adaptation (V5).

This package may *propose* changes to detection behaviour. It may never make
one. The only write into production detection state is the pre-existing
``app.ml.registry.registry.activate_model``, reached through an approved
adaptation proposal and an administrator's decision - never from here.

The boundary mirrors V4's: ``app/evaluation`` measures the system without
participating in it, and ``app/adaptation`` reasons about it without steering
it. Both exist so that the detector and the thing judging the detector are
never changed by the same hand at the same time.
"""
