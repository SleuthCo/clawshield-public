---
framework: "AI/ML Security"
version: "1.0"
domain: "AI Security"
agent: "sentinel"
tags: ["ai-security", "adversarial-ml", "model-security", "red-teaming", "prompt-injection", "ai-supply-chain"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# AI/ML Security

This document covers adversarial machine learning attacks, AI supply chain security, model provenance, AI red teaming, prompt injection defense, and guardrails architecture for securing AI systems.

## Adversarial ML Attack Taxonomy

**Overview:** Adversarial machine learning encompasses techniques used to deceive, manipulate, or exploit machine learning models. These attacks target the fundamental assumptions of ML systems: that training data is trustworthy, that model behavior is predictable, and that inference is secure.

**Attack Dimensions:**
- **Timing:** training-time vs. inference-time
- **Knowledge:** white-box (full model access) vs. black-box (API-only access)
- **Goal:** targeted (specific misclassification) vs. untargeted (any misclassification)
- **Specificity:** targeted (specific input) vs. universal (any input)

## Evasion Attacks

**Description:** Evasion attacks craft inputs at inference time that cause the model to produce incorrect outputs. The model itself is not modified; instead, the input is carefully perturbed to cross decision boundaries.

**Techniques:**
- **Fast Gradient Sign Method (FGSM):** single-step perturbation in the direction of the gradient
- **Projected Gradient Descent (PGD):** iterative, stronger version of FGSM
- **Carlini & Wagner (C&W):** optimization-based attack producing minimal perturbations
- **AutoAttack:** ensemble of attacks for robust evaluation
- **Physical-world attacks:** adversarial patches, stickers, or objects that fool vision models in real environments

**Application Domains:**
- Image classification: imperceptible pixel changes cause misclassification
- Malware detection: modify malware binaries to evade ML-based detectors
- Natural language: synonym substitution, character perturbation to bypass text classifiers
- Audio: imperceptible audio perturbations cause speech recognition errors
- Network intrusion detection: craft network traffic to evade ML-based IDS

**Defenses:**
- Adversarial training: include adversarial examples in training data
- Input preprocessing: denoising, feature squeezing, JPEG compression
- Certified defenses: provable robustness within defined perturbation bounds
- Ensemble methods: use multiple diverse models and require consensus
- Detection: identify adversarial inputs through statistical analysis
- Randomized smoothing: add calibrated noise for certified robustness guarantees

## Poisoning Attacks

**Description:** Poisoning attacks inject malicious data into the training process to influence model behavior. Effects may be immediate (degraded accuracy) or latent (backdoor activation on specific triggers).

**Attack Types:**

**Data Poisoning:**
- Inject mislabeled data to degrade overall model accuracy
- Flip labels on specific classes to cause targeted misclassification
- Poison a small percentage (0.1-1%) of training data for backdoor insertion
- Manipulate data collection pipelines (web scraping, crowdsourcing)

**Backdoor Attacks:**
- Inject trigger patterns during training that activate specific model behavior
- Triggers can be visual patterns (patches, pixel patterns), text phrases, or audio tones
- Model behaves normally on clean inputs but produces attacker-chosen output on triggered inputs
- Extremely difficult to detect without knowing the trigger
- Clean-label attacks: poisoned data appears correctly labeled

**Model Poisoning (Federated Learning):**
- Malicious participants submit poisoned model updates
- Targeted poisoning through carefully crafted gradient updates
- Exploit aggregation algorithms to amplify impact
- Model replacement attacks providing completely malicious updates

**Defenses:**
- Data provenance tracking and integrity verification
- Statistical analysis of training data distributions
- Neural Cleanse: identify and remove backdoor triggers
- Activation clustering: detect anomalous activation patterns
- Certified data removal (machine unlearning)
- Robust aggregation in federated learning (Byzantine-resilient aggregation)
- Data sanitization and filtering pipelines
- Holdout validation with clean, curated test sets

## Model Extraction Attacks

**Description:** Model extraction (model stealing) aims to recreate a functionally equivalent copy of a target model through API queries alone.

**Techniques:**
- Query the target model with crafted inputs and use responses to train a surrogate model
- Equation-solving attacks: solve for model parameters directly from input-output pairs
- Side-channel extraction: timing attacks, power analysis on model inference hardware
- Functionally equivalent extraction: surrogate model achieves similar accuracy

**Motivations:**
- Intellectual property theft: steal proprietary model architecture and training
- Facilitate evasion: use extracted model to develop adversarial examples (transferability)
- Competitive advantage: replicate competitor's ML capabilities
- Bypass rate limiting: use local copy to avoid API restrictions

**Defenses:**
- Rate limiting API queries per user and globally
- Monitor query patterns for extraction indicators (systematic probing, boundary queries)
- Watermarking: embed detectable patterns in model outputs
- Output perturbation: add calibrated noise to model predictions
- Restrict output information: return class labels only, not confidence scores
- API query analysis: detect unusual input distributions indicating extraction
- Legal protections: terms of service prohibiting model copying

## Inference Attacks

**Description:** Inference attacks extract sensitive information about training data from model behavior without directly accessing the data.

**Membership Inference:**
- Determine whether a specific data point was used in training
- Exploit the model's tendency to be more confident on training data
- Privacy concern: reveals that an individual's data was used
- Higher risk for models trained on small or sensitive datasets

**Model Inversion:**
- Reconstruct representative samples of training data from model outputs
- Recover sensitive features of training subjects (faces, medical data)
- Exploit model's learned representation to generate training-like data

**Attribute Inference:**
- Infer sensitive attributes about training data subjects
- Determine characteristics not explicitly provided as input
- Combine model outputs with auxiliary information for inference

**Defenses:**
- Differential privacy: add calibrated noise during training (DP-SGD)
- Output perturbation: add noise to model predictions
- Regularization: prevent model from memorizing specific training examples
- Federated learning: keep training data distributed (does not fully prevent)
- Knowledge distillation: train a student model that leaks less about teacher's training data
- Membership inference defenses: regularization, output masking

## AI Supply Chain Security

**Model Supply Chain Risks:**
- Pre-trained models from public repositories may contain backdoors
- Model serialization formats (Pickle, TorchScript) can execute arbitrary code
- Model weights may encode sensitive training data
- Fine-tuning datasets may be compromised
- ML framework vulnerabilities (PyTorch, TensorFlow, ONNX Runtime)

**Securing the ML Pipeline:**

**Data Stage:**
- Verify data source authenticity and integrity
- Implement data versioning with cryptographic integrity (DVC, LakeFS)
- Scan data for poisoning indicators and anomalies
- Enforce access controls on training data repositories
- Document data provenance for each dataset used

**Training Stage:**
- Secure training infrastructure with least-privilege access
- Implement training pipeline integrity (reproducible builds)
- Monitor training metrics for poisoning indicators (sudden accuracy changes)
- Protect hyperparameters and training configurations
- Use secure, attested compute environments

**Model Stage:**
- Sign models with cryptographic signatures (Sigstore/Cosign for models)
- Use safe serialization formats (SafeTensors instead of Pickle)
- Scan models for embedded malicious code
- Implement model cards documenting provenance, limitations, and evaluation
- Version control models with integrity verification

**Deployment Stage:**
- Verify model integrity before loading in production
- Run models in sandboxed, least-privilege environments
- Monitor model behavior for drift and adversarial manipulation
- Implement rollback capabilities for compromised models
- Maintain SBOM for ML dependencies

## Model Provenance

**ML Bill of Materials (ML-BOM):**
- Training data sources, versions, and preprocessing steps
- Model architecture and hyperparameters
- Training infrastructure and framework versions
- Evaluation metrics and test dataset descriptions
- Known limitations and failure modes
- Intended use and out-of-scope uses
- Ethical considerations and bias analysis

**SLSA for ML (Supply-chain Levels for Software Artifacts):**
- Level 1: documented build process for model training
- Level 2: hosted build service with source provenance
- Level 3: hardened build platform with tamper-evident provenance
- Level 4: fully verified build with hermetic, reproducible training

**Model Cards:**
- Standardized documentation for ML models
- Sections: model details, intended use, factors, metrics, evaluation data, training data, ethical considerations, caveats
- Enable informed decisions about model deployment and usage
- Required for responsible AI governance

## AI Red Teaming

**Objective:** Systematically probe AI systems to identify vulnerabilities, biases, harmful outputs, and security weaknesses before deployment and on an ongoing basis.

**Red Team Scope:**
- Prompt injection and jailbreak testing
- Bias and fairness evaluation across demographic groups
- Harmful content generation (violence, illegal activities, self-harm)
- Privacy leakage (training data extraction, PII disclosure)
- Factual accuracy and hallucination assessment
- Robustness to adversarial inputs
- Tool use and function calling abuse
- Multi-turn manipulation and goal hijacking

**Red Team Methodology:**
1. Define scope, objectives, and rules of engagement
2. Develop attack scenarios based on threat model
3. Execute systematic testing with diverse attack techniques
4. Document findings with severity, reproducibility, and evidence
5. Develop and verify mitigations for identified vulnerabilities
6. Retest to confirm mitigation effectiveness
7. Ongoing red teaming as model and system evolve

**Automated Red Teaming Tools:**
- Microsoft PyRIT: Python Risk Identification Tool for generative AI
- Garak: LLM vulnerability scanner
- NVIDIA NeMo Guardrails testing framework
- Custom prompt injection test suites
- Automated bias testing across protected categories

## Prompt Injection Defense

**Defense Layers:**

**Input Layer:**
- Input filtering for known injection patterns
- Prompt structure enforcement (template-based inputs)
- Input length and complexity limits
- Language detection and restriction
- Anomaly detection on input characteristics

**System Prompt Layer:**
- Instruction hierarchy: system-level instructions take priority
- Clear delineation between instructions and user input
- Canary tokens to detect system prompt extraction
- Minimal information in system prompts (avoid secrets, internal details)
- System prompt integrity monitoring

**Output Layer:**
- Output filtering for sensitive information (PII, credentials, system details)
- Classification of outputs for safety and policy compliance
- Structured output validation against expected schemas
- Response quality monitoring for injection indicators

**Architectural Layer:**
- Principle of least privilege for LLM tool access
- Separate execution context for user-influenced operations
- Human-in-the-loop for consequential actions
- Input sanitization between LLM output and downstream systems
- Defense in depth: multiple independent defense layers

## Guardrails Architecture

**Guardrails Design Pattern:**
Guardrails are programmable safety mechanisms that intercept, analyze, and control LLM inputs and outputs to enforce organizational policies.

**Input Guardrails:**
- Topic filtering: block off-topic or out-of-scope requests
- Toxicity detection: identify and block harmful or abusive inputs
- PII detection: identify and redact personal information in inputs
- Jailbreak detection: classify and block prompt injection attempts
- Rate limiting: prevent abuse through excessive requests
- Authentication and authorization: verify user permissions for requested operations

**Output Guardrails:**
- Factual grounding: verify claims against authoritative sources
- Hallucination detection: identify outputs not supported by provided context
- PII filtering: detect and redact sensitive information in outputs
- Content safety: block harmful, biased, or inappropriate content
- Format validation: ensure outputs conform to expected structure
- Citation verification: confirm references and sources are accurate

**Implementation Technologies:**
- NVIDIA NeMo Guardrails: programmable guardrails framework using Colang
- Guardrails AI: Python framework for structured output validation
- LangChain/LangGraph: chain-based guardrail integration
- Custom classifier models trained on organization-specific policies
- Rule-based systems for deterministic policy enforcement
- Constitutional AI: self-correcting models trained on principles

**Guardrails Operational Considerations:**
- Latency impact: guardrails add inference time; optimize for acceptable latency
- False positive management: overly strict guardrails reduce usability
- Monitoring: track guardrail trigger rates, bypass attempts, and user feedback
- Continuous update: evolve guardrails as new attack techniques emerge
- Testing: regular adversarial testing of guardrail effectiveness
- Logging: audit all guardrail decisions for review and improvement
