---
framework: "Data Collection Methods"
version: "1.0"
domain: "Research Methodology"
agent: "coda"
tags: ["data-collection", "surveys", "interviews", "sampling", "ethics", "data-quality"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

## Survey Design Principles

Surveys are structured instruments for collecting standardized data from a sample of respondents. Effective survey design follows a systematic process: define constructs, operationalize into questions, structure the instrument, pilot test, revise, and deploy.

**Question types**: Closed-ended questions (multiple choice, Likert scales, ranking, binary yes/no) enable quantitative analysis and comparability. Open-ended questions capture unanticipated responses and rich detail but require qualitative coding. Matrix questions (grids) are efficient but prone to straightlining (respondents selecting the same option across all items). Use a mix but minimize respondent burden.

**Question wording guidelines**: Use simple, unambiguous language. Avoid double-barreled questions (asking two things at once). Avoid leading questions that suggest a "correct" answer. Avoid loaded language with strong emotional connotations. Define technical terms. Specify the time frame ("in the past 30 days" vs. "recently"). Ensure response options are mutually exclusive and exhaustive. Include "prefer not to answer" and "not applicable" where appropriate.

**Likert scale design**: Use 5-point or 7-point scales for adequate discrimination. Label all points, not just endpoints, to reduce ambiguity. Decide on inclusion of a midpoint (neutral option) — include it when a neutral position is legitimate, exclude it to force a directional response. Balance positively and negatively worded items to reduce acquiescence bias, but ensure reverse-coded items are truly semantic opposites.

**Survey structure**: Begin with engaging, non-threatening questions. Group related questions thematically. Place sensitive questions (income, health behaviors, political views) later when rapport is established. Demographic questions typically come last. Use clear section headers and progress indicators. Keep total completion time under 15 minutes for general populations (under 10 minutes for online panels).

**Pilot testing**: Conduct cognitive interviews (think-aloud protocol) with 5-10 participants from the target population. Test for comprehension, relevance, and response process. Run a soft launch with a small sample to check for technical issues, skip logic errors, and preliminary response distributions. Revise based on feedback before full deployment.

## Interview Techniques

Interviews provide depth, context, and nuance that surveys cannot capture. They range from structured (fixed questions, fixed order) to semi-structured (topic guide with flexibility) to unstructured (conversational, participant-led).

**Semi-structured interview design**: Develop an interview guide with core questions and optional probes. Begin with broad, open questions ("Tell me about your experience with...") before narrowing to specific topics. Prepare follow-up probes: elaboration ("Can you tell me more about that?"), clarification ("What do you mean by...?"), example ("Can you give me an example?"), and contrast ("How does that compare to...?").

**Active listening skills**: Maintain engaged body language and verbal cues. Use reflective listening — paraphrase what the participant said to confirm understanding. Tolerate silence; respondents often continue elaborating after a pause. Avoid interrupting or completing sentences. Take minimal notes during the interview to maintain eye contact and engagement.

**Managing bias in interviews**: Be aware of social desirability bias (respondents presenting themselves favorably), interviewer effects (responses influenced by interviewer characteristics), and demand characteristics (respondents guessing what the researcher wants to hear). Use neutral language, normalize sensitive behaviors ("Many people report that..."), and probe for specifics rather than generalizations.

**Expert interviews**: When interviewing subject matter experts, demonstrate baseline knowledge to earn credibility. Ask about their specific experience rather than general knowledge. Request concrete examples and evidence rather than opinions. Probe for disagreements with prevailing views. Ask who else they recommend speaking with (snowball sampling).

**Recording and transcription**: Always obtain informed consent for recording. Use two recording devices for redundancy. Transcription options: verbatim (every word, pause, and filler), intelligent verbatim (cleaned of fillers and false starts), or summary transcription. Verbatim transcription is required for discourse analysis; intelligent verbatim suffices for thematic analysis.

## Observational Methods

Observation captures behavior as it occurs naturally, avoiding self-report biases. Types range from participant observation (researcher embedded in the setting) to non-participant observation (researcher as external observer) to systematic structured observation (predefined coding schemes).

**Structured observation**: Define the behaviors of interest, create a coding scheme with clear operational definitions, specify the observation schedule (continuous recording, time sampling, event sampling), and train observers to reliability standards (Cohen's kappa > 0.80). Pilot test the coding scheme in the actual setting.

**Ethnographic observation**: Extended immersion in a social setting to understand culture, practices, and meanings from participants' perspectives. Field notes should record: descriptive observations (what happened), reflective observations (researcher's interpretations and reactions), and methodological notes (decisions about the research process). Write field notes as soon as possible after observation sessions.

**Digital ethnography**: Observation of online communities, social media interactions, and digital behaviors. Netnography (Kozinets) provides a systematic approach: define the research question, identify and select online communities, observe and collect data, analyze and interpret, conduct member checks, and report findings. Ethical considerations include public vs. private online spaces, lurking vs. participating, and obtaining consent in open forums.

**Observer effects**: The Hawthorne effect occurs when participants change behavior because they know they are being observed. Mitigation strategies: extended observation periods (allowing habituation), unobtrusive measures, covert observation (with ethical justification), and triangulation with other data sources.

## Sampling Strategies

Sampling determines who or what is included in the study and directly affects the validity and generalizability of findings.

**Probability sampling methods**:
- Simple random sampling: Every member of the population has an equal chance of selection. Requires a complete sampling frame (list of all population members). Use random number generators, not convenience or haphazard selection.
- Stratified sampling: Divide the population into strata (subgroups) based on key characteristics, then randomly sample within each stratum. Proportional allocation mirrors population proportions; disproportional allocation oversamples small but important strata.
- Cluster sampling: Randomly select clusters (e.g., schools, neighborhoods, organizations), then sample all members or a random subset within selected clusters. Reduces cost when the population is geographically dispersed but increases sampling error (design effect).
- Systematic sampling: Select every kth element from a list after a random start. Simple to implement but vulnerable to periodicity in the list.
- Multi-stage sampling: Combines methods — e.g., randomly select regions, then districts within regions, then households within districts.

**Non-probability sampling methods**:
- Purposive sampling: Select participants who meet specific criteria relevant to the research question. Variants include maximum variation (diverse cases), homogeneous (similar cases), critical case, extreme/deviant case, and typical case sampling.
- Snowball sampling: Initial participants recruit additional participants. Useful for hidden or hard-to-reach populations but prone to network biases.
- Convenience sampling: Recruit whoever is available. The weakest form — results cannot be generalized to any defined population.
- Quota sampling: Set quotas for subgroups to ensure representation, but selection within quotas is non-random. Better than convenience sampling but not equivalent to stratified random sampling.
- Theoretical sampling (grounded theory): Sampling decisions are driven by emerging theory — select cases that will help develop, refine, or test emerging conceptual categories.

**Sample size determination**: For quantitative studies, conduct a priori power analysis (G*Power software) specifying: expected effect size, desired statistical power (typically 0.80), significance level (typically 0.05), and the planned statistical test. For qualitative studies, sample until theoretical saturation — the point at which new data no longer generate new conceptual insights. Guest, Bunce, and Johnson (2006) found saturation often occurs within 12 interviews for homogeneous populations, but this is a rough guideline, not a rule.

## Data Quality Frameworks

Data quality is multidimensional. The FAIR principles (Findable, Accessible, Interoperable, Reusable) guide data management, while specific quality dimensions address different aspects.

**Core quality dimensions**: Accuracy (data correctly represent the real-world entity), completeness (all required data elements are present), consistency (data do not contradict each other across sources), timeliness (data are sufficiently current for the intended use), validity (data conform to defined formats and business rules), and uniqueness (no unintended duplicates).

**Data validation techniques**: Range checks (values within acceptable bounds), format checks (consistent data types and patterns), cross-field validation (logical consistency between related fields), duplicate detection (exact and fuzzy matching), referential integrity (foreign keys reference valid records), and historical consistency (changes over time are plausible).

**Missing data handling**: Missing Completely at Random (MCAR) — missingness is unrelated to any variables. Missing at Random (MAR) — missingness depends on observed variables. Missing Not at Random (MNAR) — missingness depends on the missing value itself. Strategies: complete case analysis (listwise deletion — only valid for MCAR and small amounts of missingness), multiple imputation (appropriate for MAR), maximum likelihood estimation, and sensitivity analysis to assess impact of missing data assumptions.

**Data provenance**: Document the origin, transformation, and movement of data. Record: the original source, date of collection, collection method, any transformations applied, who performed each step, and quality checks conducted. Provenance enables reproducibility and supports confidence assessments.

## Ethical Data Collection

Ethical data collection protects participants, ensures integrity, and maintains public trust in research.

**Informed consent elements**: Purpose of the research, procedures involved, expected duration, potential risks and discomforts, potential benefits, confidentiality protections, voluntary nature and right to withdraw, contact information for the researcher and IRB/ethics committee, and any compensation provided. Consent must be ongoing — participants can withdraw at any time.

**Vulnerable populations**: Children, prisoners, pregnant women, cognitively impaired individuals, economically disadvantaged populations, and those in power imbalances with the researcher require additional protections. Assent (agreement to participate) is required from children in addition to parental consent. Institutional review boards apply heightened scrutiny to research with vulnerable populations.

**Confidentiality and anonymity**: Anonymity means no identifying information is collected — the researcher cannot link responses to individuals. Confidentiality means identifying information is collected but protected. De-identification removes direct identifiers (names, SSNs). Pseudonymization replaces identifiers with codes. K-anonymity ensures each record matches at least k-1 other records on quasi-identifiers. Assess re-identification risk before sharing any data.

**Data protection by design**: Collect only necessary data (data minimization). Encrypt data in transit and at rest. Implement access controls with the principle of least privilege. Maintain audit logs. Define retention periods and destruction procedures. Conduct Data Protection Impact Assessments (DPIAs) for high-risk processing activities. Comply with applicable regulations (GDPR, HIPAA, FERPA, state/national laws).

**Digital research ethics**: Web scraping may violate terms of service. Social media research ethics are evolving — the Association of Internet Researchers (AoIR) provides guidelines. Consider: Is the data truly "public"? Would participants expect their data to be used for research? Could the research cause harm to individuals or communities? Is aggregation of public data creating new privacy risks? Contextual integrity (Nissenbaum) — information flows should match norms appropriate to the context in which data was originally shared.

## Multi-Modal Data Collection

Combining multiple data collection methods strengthens research through triangulation — convergence of findings across methods increases confidence; divergence reveals complexity and prompts deeper investigation.

**Triangulation types**: Data triangulation (multiple sources), investigator triangulation (multiple researchers), theory triangulation (multiple theoretical perspectives), methodological triangulation (multiple methods), and environmental triangulation (multiple settings).

**Sequential designs**: Qualitative exploration followed by quantitative measurement (scale development, hypothesis generation). Quantitative measurement followed by qualitative explanation (understanding outliers, interpreting unexpected results).

**Concurrent designs**: Simultaneous data collection using multiple methods. Requires careful planning to ensure data can be meaningfully integrated. Joint displays (matrices that juxtapose quantitative and qualitative findings) facilitate integration.

**Digital trace data**: Server logs, transaction records, sensor data, social media posts, and other passively collected digital data complement traditional research methods. Advantages: non-reactive, continuous, large-scale. Disadvantages: limited to observable behavior, may not capture intention or meaning, and raise privacy concerns. Always combine with methods that capture context and meaning.

## Field Data Collection Logistics

Practical planning determines whether a well-designed study succeeds or fails in execution.

**Field team management**: Recruit data collectors who match the target population on key characteristics (language, cultural familiarity). Train extensively on the protocol, including role-playing difficult scenarios. Standardize procedures through detailed manuals. Monitor quality through supervision, spot checks, audio recording, and regular debriefs.

**Instrument translation**: Use back-translation (translate to target language, then independently translate back to source language, compare). Committee translation (bilingual panel reaches consensus) is often preferred for cultural adaptation beyond literal translation. Pilot test the translated instrument with native speakers. Validate measurement equivalence through factor analysis across language versions.

**Data management in the field**: Use electronic data capture (tablets, smartphones) where possible for real-time validation and skip logic. Implement daily data quality checks. Back up data to multiple locations. Maintain a field log documenting decisions, challenges, and deviations from protocol. Track response rates and non-response patterns throughout collection.
