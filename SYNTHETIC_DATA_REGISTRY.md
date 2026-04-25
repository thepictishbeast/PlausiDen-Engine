# Synthetic Data + Fake-Detection Registry

Authoritative triage of public synthetic-data generators and fake-data
detection tools, evaluated for value to PlausiDen-Engine (data-pollution
synthesis primitives), PlausiDen-Pollution (synthetic analytics events),
and LFI (training data + adversarial validation).

The two halves of this registry — **generators** and **detectors** — are
adversarial counterparts. PlausiDen-Engine produces synthetic forensic
artifacts; the detector half is the adversary that tries to tell our
output apart from real data. Both are equally important: a detector you
*don't* know about is worse than one you do.

Mirrors the per-repo registry discipline established across the
PlausiDen ecosystem.

## Status definitions

| Status | Meaning |
|---|---|
| **adopted** | Vendored or wired in. |
| **adopted-as-dep** | Used directly via package manager / git submodule; no fork. |
| **deferred** | Genuine value but waiting on a specific trigger. |
| **reference-only** | Pattern source / paper / design we read, did not absorb. |
| **rejected** | Considered and ruled out; **do not re-evaluate without new evidence**. |

## Current stack baseline

PlausiDen-Engine is **Rust + LFI-driven generation primitives**.
PlausiDen-Pollution is **synthetic analytics events with HMAC tagging**.
LFI training surface accepts **multi-source corpora**.

Candidates are judged by three tests:

1. (Generator) Does it open a synthesis primitive (tabular / time-series / text / graph / image / audio) we don't have?
2. (Detector) Does it surface a discrimination signal we don't currently defeat?
3. Does it operate offline / no-SaaS / local-runnable?

If none of (1)/(2)/(3), defer or reject.

---

## GENERATORS

### Tier A — high-value synthesis frameworks

| Tool | Stars | Lang | Status | Target | Notes |
|---|---|---|---|---|---|
| **gretelai/gretel-synthetics** | 677 | Python | reference-only | Engine + LFI | **The canonical FOSS DP-aware synthetic-data lib.** Differential privacy + structured/unstructured text. Read for the privacy parameters + the model-training pipeline; LFI's training-data side could mirror the API for synthetic augmentation. |
| **hitsz-ids/synthetic-data-generator** | 2,416 | Python | reference-only | Engine | Comprehensive structured tabular synthesis. Recent, large user base. Reference for tabular-data realism patterns. |
| **argilla-io/synthetic-data-generator** | 573 | Python | reference-only | LFI | "Build datasets using natural language" — modern LLM-driven approach. Reference for prompt-driven synthesis if LFI needs Q&A pair generation. |
| **databrickslabs/dbldatagen** | 457 | Python | reference-only | Engine + LFI | Spark-scale synthetic data. Reference if Engine ever needs to generate at corpus-scale (multi-GB training sets). |
| **Belval/TextRecognitionDataGenerator** | 3,665 | Python | reference-only | Engine | Synthetic text-recognition (OCR-target) image generation. Reference if Engine adds OCR-targeted noise. |
| **Data-Centric-AI-Community/fg-data-synthetic** | 1,626 | Jupyter | reference-only | Engine + LFI | Tabular + time-series synthesis playbook. Notebook-format = good for prototyping. |
| **Unity-Technologies/PeopleSansPeople** | 325 | C# | reference-only | Engine | Privacy-preserving human-centric synthetic data. Unity (C#); not absorbing, but the privacy-preserving humans angle is rare and worth knowing. |
| **syncora-ai/syncora-benchmarks** | 711 | Jupyter | reference-only | Engine + Pollution | **Synthetic-data BENCHMARK kit.** Compares generators on quality metrics. **Direct relevance:** use this kind of benchmark to test how convincing PlausiDen-Engine output is. Adversarial measurement. |
| **Nike-Inc/timeseries-generator** | 156 | Python | reference-only | Engine | Time-series synth with factor-driven generation. Clean API. Reference for Engine's time-series surface (GPS traces, network packet timing). |
| **microsoft/CodeMixed-Text-Generator** | 60 | Jupyter | reference-only | LFI | Code-mixed text (multilingual synthetic). Reference if LFI ever needs multilingual training. |
| **sodadata/messydata** | 32 | Python | reference-only | Engine + Pollution | **DIRTY data generator.** Critical insight: real data is messy. Clean synthetic is detectable. Reference for adding realistic noise/errors/typos to PlausiDen-Engine output — this is one of the highest-leverage anti-detection moves. |
| **neulab/data-agora** | 41 | Jupyter | reference-only | LFI | ACL 2025 paper on evaluating LLMs as synthetic data generators. Read the eval methodology. |
| **sileod/reasoning-core** | 37 | Python | reference-only | LFI | Procedural data generators for synthetic pretraining + formal reasoning. Reference for LFI's reasoning-corpus generation. |

### Tier B — narrower-scope generators

| Tool | Stars | Lang | Status | Target | Notes |
|---|---|---|---|---|---|
| **yindz/common-random** | 654 | Java | reference-only | Pollution | **Localized fake-data generator (Chinese-specific formats).** Pattern reference for the Pollution localized-realism trick — geo-valid synthetic IDs / addresses / phone numbers. Generalize to other locales. |
| **benkeen/generatedata** | 2,274 | TypeScript | reference-only | Engine | Web-based test data generator. Read the data-type catalog; useful menu of "what kinds of fake data do real apps need?" |
| **danibram/mocker-data-generator** | 427 | TypeScript | reference-only | Engine | Schema-based mock-data generator (uses faker.js). Reference for schema-driven Engine output. |
| **gongouveia/Whisper-Synthetic-ASR-Dataset-Generator** | 32 | Python | reference-only | LFI | Audio synth for Whisper ASR training. Reference if LFI gains audio surface. |
| **nalinrajendran/synthetic-LLM-QA-dataset-generator** | 59 | Python | reference-only | LFI | LLM Q&A pair generator. Reference for LFI Q&A training. |
| **DeepAI-Research/Simverse** | 32 | Python | reference-only | Engine | Image / video / 3D synthesis. Niche. |
| **InternRobotics/InternDataEngine** | 104 | Python | reference-only | — | High-fidelity synthetic for robotic manipulation. Off-thesis for current PlausiDen scope. |
| **ligengen/EgoGen** | 89 | Python | reference-only | — | Egocentric synthetic (CVPR 2024). Off-thesis. |
| **ldbc/ldbc_snb_datagen_spark** | 183 | Java | reference-only | LFI | LDBC social-network benchmark graph generator. Reference if LFI ever does graph training. |
| **zakimjz/IBMGenerator** | 30 | C++ | reference-only | LFI | IBM Synthetic Data Generator for itemsets/sequences. Old (the canonical pattern-mining benchmark). Reference for sequence-mining training data. |

### Rejected generators

| Tool | Reason |
|---|---|
| **ZieIony/RandomData** | Generic Java random data. No unique signal. |
| **StefH/RandomDataGenerator** | Generic C#. No unique signal. |
| **m4bwav/DotNetRandomNameGenerator** | Narrow .NET name generator. |
| **kedarvj/mysql-random-data-generator** | MySQL-specific filler. Niche. |
| **ATISLabs/SyntheticDatasets.jl** | Julia, abandoned 2023. |
| **danielkrause/DCASE2022-data-generator** | Niche audio benchmark (DCASE 2022). |
| **garystafford/streaming-sales-generator** | Sales-stream-only. Niche. |
| **paulstreli/3D-Hand-Pose-Sequence-Data-Augmentation-using-GANs** | Niche hand-pose GAN. Off-thesis. |
| **MichaelLiLee/Synthetic-Data-Generator-for-Human-Detection** | Blender + Python human-detection, niche. |
| **Tachikoma87/SyntheticHumanDatasetGenerator** | Same niche. |
| **KoharuLee/SynData-Gen** | Generic, no clear differentiator. |
| **jj-tech-io/Synthetic-Data-Pipeline-Blender** | Blender pipeline. Off-thesis. |
| **kumarsum-hub/Bitwise** | Unclear scope. |
| **kinit-sk/RoSE** | Academic, narrow. |
| **shantanurathore/LLM-UseCases-physician-narrative-generator** | Medical narratives. Niche. |
| **amantha6/SynthEval-Automated-Code-Review-Dataset-Generator** | Code review datasets. Niche. |
| **arya-rehpade/Stylegan-face-generator** | StyleGAN faces. Niche / off-thesis. |
| **katherinejin12/VLM-dataset-generator** | NVIDIA Isaac Sim VLM. Niche. |
| **makinarocks/Mandrova** | Sensor data. Off-thesis. |
| **amirmgh1375/TextRecognitionDataGenerator** | Duplicate of Belval/TextRecognitionDataGenerator. |

---

## DETECTORS (adversarial counterparts to Engine output)

This is the side of the field that *tries* to tell synthetic from real.
**Reading the detectors is non-negotiable** — every synthetic-data project
that doesn't know its discriminators is producing theatrical PD.

### Tier A — direct discrimination-signal references

| Tool | Stars | Lang | Status | Target | Notes |
|---|---|---|---|---|---|
| **aloth/origin-lens** | 2 | Dart | reference-only | Pollution + Engine | **C2PA Content Credentials verification.** This is the EMERGING industry standard for cryptographically attesting "this image came from this camera at this time." If Engine outputs images and they LACK valid C2PA chains, that's a discrimination signal. **Read the C2PA spec via this client.** |
| **thandal/fakeproof_tools** | 2 | C | reference-only | Pollution | "Metadata/sensor/location extraction tools for FakeProof MP4 recordings." Mirrors what a forensic analyst pulls out of synthetic video to detect tampering. Reference for what to *fake* in MP4 metadata. |
| **z1311/Fake-Aadhaar-Detection** | 15 | Python | reference-only | Engine + Pollution | Two-stage classifier (image-level + text-level) for Aadhaar (Indian ID) authenticity. Reference for **what discriminators actually look at** when checking ID authenticity. Same threat model applies to any synthetic-ID-document output. |
| **mesmacosta/bq-fake-pii-table-creator** | 14 | Python | reference-only | Pollution | Generates fake PII tables in BigQuery for testing. Pattern reference: how *defensive* teams generate fake PII to test their detectors. |

### Tier B — fake-account / fake-content detection (signal references)

| Tool | Stars | Lang | Status | Target | Notes |
|---|---|---|---|---|---|
| **isspek/FakeNewsDetectionFramework** | 3 | Python | reference-only | Engine | Research prototype for early fake-news detection in social media. Read for what features a fake-news classifier extracts. |
| **Rafna123/Instagram-Fake-Account-Detector** | 2 | Jupyter | reference-only | Pollution | Detects fake IG accounts via metadata + behavior + image. Reference for what signals a fake-account detector uses. |
| **PhilippWiessner/Hierachical_GNN_for_Fake_News_Detection** | 1 | Python | reference-only | LFI | GNN-based detection — reference for graph-structural signals in fake content. |
| **AnushaHardaha/APK-Detector** | 2 | JS | reference-only | — | Detects fake banking APKs. Niche but reference for app-level signals. |
| **NS-AlgoHub/fake_job_posting_detection** | 3 | Python | reference-only | — | Job-posting classifier. Reference for text-classifier feature extraction. |

### Cloud-metadata fake-services (test infrastructure, not detection per se)

| Tool | Stars | Lang | Status | Target | Notes |
|---|---|---|---|---|---|
| **space88man/metadata-service** | 3 | Python | reference-only | — | Fake OpenStack metadata service for cloud-init. Reference if PlausiDen-Pollution ever produces synthetic cloud-instance metadata. |
| **zchee/compute-metadata-server** | 3 | Go | reference-only | — | Fake GCE compute metadata server for testing. Same pattern. |
| **bpholt/fake-ec2-metadata-service** | — | — | reference-only | — | Same idea, EC2-flavored. |
| **stefansundin/vagrant-ec2-metadata** | — | — | reject | — | Vagrant-specific shim. Off-thesis. |

### Rejected detectors

| Tool | Reason |
|---|---|
| **Deekshith06/Fake-Social-Media-Account-Detector** | Narrow student project. |
| **pranshurawte/Fake-Instagram-Profile-Detector** | Same. |
| **PearlAngeline/Fake-Drug-Detection** | Pharmaceutical, off-thesis. |
| **csheldonhess/FakeConsumer** | Unclear scope. |
| **0xLava101/fake_take** | Unclear scope. |
| **marianlonga/FakeNews** | Student project. |
| **MSMirshamsi/FakeNewsDetection** | Student project. |
| **ashwanirajan/Fake-News-Detector** | Student project, narrow. |
| **XBACTYN/Fake-image-detector-agregator-NN-** | 1★, vague. |
| **GuillainM/FLAC_Detective** | FLAC audio forensics. Niche off-thesis. |
| **rumenjordanov/fake-gym-wifi-attack-demo** | Wi-Fi attack demo. Off-thesis. |
| **amigan/fakedbfs** | DBFS file system. Off-thesis. |
| **PrafulKumar-1/unmasking-the-puppet-masters-...** | Student final, narrow. |
| **NishNishendanidu/mtroid-bot** | Discord bot, off-thesis. |
| **Wallace-Best/best** | Unclear scope, no description. |
| **Swaroop-hub5/b2b-transaction-anomaly-detector** | Anomaly detection, off-thesis. |
| **z1311/Fake-Aadhaar-Detection.git (dup)** | Duplicate of above. |
| **github.com/search?q=fake+metadata...** | A GitHub search URL, not a repo. Skip. |

---

## Adversarial validation strategy (the supersociety move)

The deepest insight from this triage: **PlausiDen-Engine and PlausiDen-
Pollution should be measured against the detector half of this list as a
formal CI gate.** Concretely:

1. **Pick three or four detector references** (Aadhaar-style image
   classifier, fake-news classifier, fake-account-metadata classifier,
   C2PA-verifier) and reimplement their feature extraction in a
   `pollution-discriminator-bench` tool.
2. **Run Engine output through it** as part of pre-merge CI. Track the
   detection rate over time.
3. **A regression in undetectability is a bug.** A new detector technique
   we don't defeat is a P0 design issue, not a "nice to have."

This is layered defense applied to the synthesis side: knowing the
adversary's tools, locally, in CI, before the adversary uses them on
real consumer data. **Adversarial validation is the only honest measure
of plausible deniability.**

---

## Decision rules

1. **Stack alignment**: Python is acceptable for *reference reading*
   (most synthetic-data work is Python). For absorption, stay in Rust.
2. **Generator-detector pairing**: every generator absorbed must be
   benchmarked against a corresponding detector. Asymmetric absorption
   produces theatrical PD.
3. **Maintenance posture**: no commits in 18 months → reference-only at
   most.
4. **PSA filter**: SaaS / phones home → reject. (Most candidates pass;
   the ones that don't are flagged.)
5. **Acronym discipline**: "synthetic data" covers everything from
   tabular fillers to GAN faces; categorize by *output type* + *target
   use case*, not by buzzword.

## Triggers for the deferred set

(None deferred currently — all entries either reference-only or
rejected. The reasoning: synthesis primitives are paper-grade and
implementable directly in Rust; vendoring Python wholesale would
create stack-mismatch debt.)

If a future trigger arises:

| Capability | Reference to start from |
|---|---|
| Differential-privacy synth | gretelai/gretel-synthetics |
| Tabular-realism patterns | hitsz-ids/synthetic-data-generator |
| Localized-fake-ID generation | yindz/common-random (then port to other locales) |
| Time-series realism | Nike-Inc/timeseries-generator |
| Adversarial-bench against real detectors | aloth/origin-lens (C2PA) + z1311 (ID classifiers) |
| Realistic-noise injection | sodadata/messydata |
| Synthetic-data quality metrics | syncora-ai/syncora-benchmarks |

## Refresh cadence

Quarterly, alongside the other registries. Rejected items stay rejected
unless new evidence arrives.
