---
framework: "Research Design & Methodology"
version: "1.0"
domain: "Research Methodology"
agent: "coda"
tags: ["research-design", "hypothesis", "mixed-methods", "literature-review", "systematic-review", "meta-analysis"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

## Research Question Formulation

A well-formed research question is the foundation of any investigation. Use the FINER criteria to evaluate research questions: Feasible (answerable with available resources), Interesting (to the investigator and stakeholders), Novel (confirms, refutes, or extends existing knowledge), Ethical (passes IRB or ethical review), and Relevant (to scientific knowledge, policy, or practice).

The PICO framework structures clinical and empirical questions: Population (who), Intervention/Exposure (what), Comparison (against what), Outcome (measured how). For qualitative research, use PICo: Population, phenomenon of Interest, Context.

Research questions exist on a spectrum of specificity. Descriptive questions ask "what is happening?" (e.g., "What is the prevalence of X?"). Relational questions ask "what is the relationship between A and B?" Causal questions ask "does A cause B?" Each type demands different methodological approaches and evidence standards.

Operationalization is the process of translating abstract concepts into measurable variables. Define constructs clearly, identify observable indicators, and specify measurement procedures. Poor operationalization is the most common source of construct validity threats.

## Hypothesis Development

Hypotheses are testable predictions derived from theory or prior observation. A strong hypothesis is specific, falsifiable, grounded in existing evidence, and parsimonious. The null hypothesis (H0) states no effect or relationship exists; the alternative hypothesis (H1) states the predicted effect or relationship.

Directional hypotheses predict the direction of an effect (e.g., "Group A will score higher than Group B"). Non-directional hypotheses predict a difference without specifying direction. Choose based on theoretical justification and the strength of prior evidence.

Develop hypotheses through: deductive reasoning from established theory, inductive reasoning from observed patterns, abductive reasoning (inference to the best explanation), and analogical reasoning from similar domains. Document the theoretical basis for each hypothesis to support later interpretation.

Pre-registration of hypotheses before data collection prevents HARKing (Hypothesizing After Results are Known) and p-hacking. Platforms like OSF Registries and AsPredicted provide timestamped records. Distinguish between confirmatory hypotheses (pre-registered) and exploratory analyses (generated during analysis).

## Mixed-Methods Research Design

Mixed-methods research integrates quantitative and qualitative approaches to leverage complementary strengths. Creswell and Plano Clark identify core designs:

**Convergent Design**: Collect quantitative and qualitative data simultaneously, analyze separately, then merge results for comparison. Use when you need to validate quantitative results with qualitative findings or compare different perspectives on the same phenomenon.

**Explanatory Sequential Design**: Collect and analyze quantitative data first, then use results to inform qualitative data collection. Use when quantitative results need explanation or elaboration (e.g., unexpected findings, outlier cases).

**Exploratory Sequential Design**: Collect and analyze qualitative data first, then use findings to develop quantitative instruments or hypotheses. Use when existing measures are inadequate or the phenomenon is poorly understood.

**Embedded Design**: One data type plays a supplemental role within a primarily quantitative or qualitative study. Use when a secondary data source can address a question that the primary approach cannot.

Integration strategies include: merging (side-by-side comparison in joint displays), connecting (one phase informs the next), building (qualitative findings develop quantitative measures), and embedding (supplementary data within a larger design).

Quality criteria for mixed-methods include both quantitative validity/reliability and qualitative trustworthiness, plus integration quality — how well the two strands inform each other.

## Literature Review Methodology

Effective literature reviews follow a systematic search process. Define inclusion/exclusion criteria before searching. Use Boolean operators (AND, OR, NOT) to combine search terms. Develop a search string iteratively, testing and refining across databases.

Search multiple databases appropriate to the domain: PubMed/MEDLINE (biomedical), PsycINFO (psychology), Web of Science (multidisciplinary), Scopus (multidisciplinary), ERIC (education), EconLit (economics), IEEE Xplore (engineering/computing). Use Google Scholar for breadth but not as a sole source due to inconsistent coverage and quality filtering.

Supplement database searches with: citation chaining (forward and backward), hand-searching key journals, contacting domain experts, checking reference lists of included studies, and searching grey literature (dissertations, conference proceedings, working papers, government reports).

Organize literature using a structured extraction matrix. Columns typically include: citation, research question, methodology, sample, key findings, limitations, and relevance to your question. Tools like Zotero, Mendeley, or Rayyan facilitate management and de-duplication.

Synthesize thematically rather than study-by-study. Identify patterns, contradictions, and gaps across the literature. A narrative synthesis weaves findings into a coherent story. A conceptual framework synthesis maps relationships between key concepts identified across studies.

## Systematic Review Methodology

Systematic reviews follow the PRISMA (Preferred Reporting Items for Systematic Reviews and Meta-Analyses) guidelines. Key steps:

1. **Protocol development**: Define the review question (PICO), eligibility criteria, search strategy, data extraction plan, and analysis approach. Register the protocol on PROSPERO or OSF.

2. **Comprehensive searching**: Search a minimum of two databases plus supplementary sources. Document every search string, database, date, and result count. Aim for reproducibility.

3. **Study selection**: Two independent reviewers screen titles/abstracts, then full texts. Calculate inter-rater agreement (Cohen's kappa). Resolve disagreements through discussion or a third reviewer. Document reasons for exclusion at the full-text stage.

4. **Data extraction**: Use a standardized extraction form piloted on a subset of studies. Two reviewers extract independently. Record study characteristics, participant details, interventions, outcomes, and results.

5. **Risk of bias assessment**: Use validated tools — Cochrane Risk of Bias (RoB 2) for RCTs, ROBINS-I for non-randomized studies, Newcastle-Ottawa Scale for observational studies, CASP checklists for qualitative research.

6. **Synthesis**: Narrative synthesis for heterogeneous studies. Meta-analysis when studies are sufficiently homogeneous in participants, interventions, comparators, and outcomes.

7. **GRADE assessment**: Rate certainty of evidence across outcomes using the GRADE framework (Grading of Recommendations, Assessment, Development and Evaluations) — considering risk of bias, inconsistency, indirectness, imprecision, and publication bias.

## Meta-Analysis Approaches

Meta-analysis statistically combines effect sizes from multiple studies to estimate an overall effect. Prerequisites: studies must address sufficiently similar questions, report comparable outcomes, and be of acceptable methodological quality.

**Effect size calculation**: Convert study results to a common metric. For continuous outcomes: standardized mean difference (Cohen's d, Hedges' g) or mean difference. For binary outcomes: odds ratio, risk ratio, or risk difference. For correlations: Pearson's r or Fisher's z-transformed r.

**Fixed-effects vs. random-effects models**: Fixed-effects assumes all studies estimate the same true effect (appropriate when studies are functionally identical). Random-effects assumes true effects vary across studies and estimates the mean of the distribution of effects (appropriate when studies differ in populations, settings, or implementations). In practice, random-effects models are more common and conservative.

**Heterogeneity assessment**: Q statistic tests whether variability in effect sizes exceeds sampling error. I-squared quantifies the percentage of variability due to true heterogeneity (25% = low, 50% = moderate, 75% = high). Tau-squared estimates the between-study variance. Prediction intervals show the range of effects expected in future studies.

**Moderator analysis**: Subgroup analysis compares effect sizes across categorical moderators. Meta-regression examines continuous moderators. Both are observational (not causal) and should be pre-specified to avoid data dredging.

**Publication bias assessment**: Funnel plots visualize the relationship between effect size and precision. Asymmetry suggests bias. Statistical tests include Egger's regression, Begg's rank correlation, and trim-and-fill estimation. The p-curve and p-uniform methods assess evidential value.

**Sensitivity analysis**: Assess robustness by removing one study at a time (leave-one-out), restricting to low risk-of-bias studies, using alternative effect size measures, or comparing fixed and random-effects models.

## Research Design Selection Guide

Selecting the appropriate research design depends on the research question, available resources, ethical constraints, and the current state of knowledge.

**Experimental designs** (randomized controlled trials) provide the strongest evidence for causal claims. Use when: you can manipulate the independent variable, random assignment is feasible and ethical, and you need to establish causation. Threats: selection bias (if randomization fails), attrition, contamination between groups.

**Quasi-experimental designs** (difference-in-differences, regression discontinuity, instrumental variables, propensity score matching) approximate experimental conditions without randomization. Use when: randomization is infeasible or unethical, but you still need causal inference. Require careful attention to confounding and selection bias.

**Observational designs** (cohort, case-control, cross-sectional) describe associations without manipulation. Cohort studies follow exposed and unexposed groups forward in time. Case-control studies compare cases (with outcome) to controls (without). Cross-sectional studies measure exposure and outcome simultaneously. Observational designs cannot establish causation without additional assumptions.

**Qualitative designs** (phenomenology, ethnography, case study, grounded theory, narrative inquiry) explore meaning, experience, and context. Use when: the phenomenon is poorly understood, context matters deeply, or you need to understand "how" and "why" rather than "how much." Quality criteria: credibility, transferability, dependability, confirmability (Lincoln and Guba's trustworthiness framework).

## Validity and Reliability Frameworks

**Internal validity**: The degree to which observed effects are attributable to the independent variable rather than confounds. Threats include: history, maturation, testing effects, instrumentation changes, statistical regression to the mean, selection bias, and attrition.

**External validity**: The degree to which findings generalize beyond the study context. Threats include: sample non-representativeness, setting specificity, temporal specificity, and treatment-context interactions.

**Construct validity**: The degree to which measures capture the intended constructs. Threats include: inadequate operationalization, mono-method bias, experimenter expectancy, and participant reactivity (Hawthorne effect, demand characteristics).

**Statistical conclusion validity**: The degree to which statistical inferences are accurate. Threats include: low statistical power, violated assumptions, multiple comparisons without correction, unreliable measures, and restriction of range.

**Reliability types**: Test-retest (stability over time), inter-rater (agreement between observers), internal consistency (Cronbach's alpha, McDonald's omega), parallel forms (equivalence of alternative measures). Reliability sets an upper bound on validity — an unreliable measure cannot be valid.

## Ethical Considerations in Research Design

All research involving human participants requires ethical review. Core principles from the Belmont Report: respect for persons (informed consent, protection of vulnerable populations), beneficence (maximize benefits, minimize harms), and justice (fair distribution of research burdens and benefits).

Informed consent requires: disclosure of purpose, procedures, risks, and benefits; comprehension by participants; voluntariness without coercion; and the right to withdraw at any time without penalty. Waiver of consent may be justified when research involves minimal risk and consent is impracticable (e.g., analysis of de-identified records).

Data protection requires compliance with applicable regulations (GDPR, HIPAA, FERPA). Implement data minimization (collect only what is needed), anonymization or pseudonymization, secure storage with access controls, and defined retention and destruction schedules.

Research integrity demands: honest reporting of methods and results, no fabrication or falsification, proper attribution and avoidance of plagiarism, disclosure of conflicts of interest, and transparent handling of negative or inconvenient results.
