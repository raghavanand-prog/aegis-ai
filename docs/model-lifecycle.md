# Model lifecycle

```
corpus ─► validation ─► features ─► fit ─► held-out scoring ─► artifact
       ─► sha256 ─► registry row ─► (optionally) activate ─► inference
```

## Training is an explicit operator action

```bash
cd backend
python -m app.ml.training.train_anomaly_model
```

It deliberately does **not** happen on application startup. A backend that
silently retrains on every restart has no reproducible detection behaviour, and
"the model changed when the pod restarted" is not a sentence anyone wants to say
during an investigation.

Useful flags: `--samples`, `--seed`, `--span-days`, `--contamination`,
`--n-estimators`, `--no-activate`, `--format json`.

## The training corpus

`app/ml/training/corpus.py` builds it from the same synthetic generator that
feeds the live pipeline, through the same normalizer and the same feature
extractor. Using a different generator for training would teach the model a
distribution the running system never produces.

Two deliberate choices:

* **Timestamps are spread across simulated days** with a realistic daily rhythm.
  The generator stamps everything "now", which would leave every temporal
  feature constant and the model blind to off-hours activity. Anchored to a
  fixed epoch, so the same seed produces a byte-identical corpus.
* **Nothing is labelled.** This is unsupervised training. The scenario name is
  carried only so the report can describe the mix, and is never used as a
  target.

## Nothing is registered unless it can be re-read

The artifact is written, its SHA-256 taken, and then **loaded straight back**
before a registry row is created. A half-trained model cannot become the active
one.

## The registry

`ml_models`, one row per `(name, version)`. Small on purpose — the requirement
is reproducibility, not an MLOps platform.

Recorded: model type, feature schema version, dataset version and fingerprint,
training sample count, hyperparameters, metrics, feature names, artifact path,
artifact SHA-256, status, who created it, when it was trained and activated.

Two rules the registry enforces:

* **Versions are immutable.** Registering an existing version is refused. Every
  `ml_inferences` row names the version that produced it; if a version could be
  overwritten, every one of those rows would become unverifiable.
* **At most one active version per model name.** Activating archives the
  incumbent — which is what makes rollback a one-line operation.

Model names and versions are validated as single safe path components, and the
resolved artifact path is checked to be inside the artifact directory. Refused
rather than sanitised: silently rewriting `../../etc` to `etc` produces a path
that is safe but is not the one the caller asked for.

## Activation, rollback, deactivation

| Endpoint | Role | Effect |
| --- | --- | --- |
| `POST /ml/models/{id}/activate` | admin | Serves this version, archives the incumbent, reloads the engine immediately. |
| `POST /ml/models/{id}/deactivate` | admin | Stops serving. No active model = rules-only, a supported state. |
| `POST /ml/models/rollback` | admin | Reactivates the most recently archived version. |

**Analysts cannot deploy models.** Activating one changes what the whole
platform detects, which is not an ordinary analyst action. Tests assert both the
viewer and analyst 403.

Every action is audited (`ml.model_trained`, `ml.model_activated`,
`ml.model_deactivated`, `ml.model_rollback`).

## Artifacts are not in git

`app/ml/artifacts/` is gitignored. Model binaries do not belong in version
control: they are large, opaque, and reproducible from a seed. `ML_MODEL_DIR`
points wherever you want them — a mounted volume, an object-store mount.

A fresh developer reproduces the model with one command; the same seed produces
the same artifact.

## The digest matters

`artifact_sha256` is checked on every load. An artifact whose hash no longer
matches the registry has been altered on disk, and a tampered model is a
detection engine that lies — the engine refuses to load it and reports why.

## Feature schema compatibility

Every artifact records the feature schema version and the exact feature
ordering it was fitted on. At load time both are compared with the running
build; a mismatch is refused. Scoring a vector the model was never fitted on
would produce a confident number that means nothing.

Changing `FEATURE_NAMES` therefore means bumping `FEATURE_SCHEMA_VERSION` and
retraining. Old inference rows stay interpretable because each names the schema
version it used.

## Choosing the threshold

The threshold lives in configuration, not in the model, so it can be tuned
without retraining. Training reports a measured calibration table — the flagged
rate at candidate thresholds on held-out data the fit never saw — plus a
recommended value (the score above which ~1% of ordinary traffic sits):

```
Flagged rate by threshold (held-out, unseen during fitting):
  0.55   28.00%  ################
  0.60    9.67%  #####
  0.65    1.25%
  0.70    0.08%
  0.75    0.00%
```

An operating point chosen without seeing that table is chosen arbitrarily. See
[EVALUATION.md](EVALUATION.md) for why the shipped default is 0.65.

## What is deliberately absent

No automatic retraining, no adaptive thresholds, no autonomous deployment, no
active learning. V3 establishes the foundation for those; building them before
there is a reproducible baseline to measure against would mean changing the
detector and the yardstick at the same time.
