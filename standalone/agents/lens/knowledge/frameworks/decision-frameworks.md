---
framework: "Decision Frameworks"
version: "1.0"
domain: "Decision Analysis"
agent: "coda"
tags: ["cynefin", "OODA", "decision-matrix", "expected-value", "MCDA", "delphi-method"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

## Cynefin Framework

The Cynefin framework, developed by Dave Snowden, categorizes situations into five domains based on the relationship between cause and effect. Each domain requires a different management and decision-making approach.

**Clear (formerly Simple/Obvious)**: Cause and effect are obvious to all. Best practices exist and can be applied. Approach: Sense-Categorize-Respond. Identify the situation, categorize it according to established rules, and apply the known best practice. Risk: complacency — treating complex situations as clear because of overconfidence or oversimplification.

**Complicated**: Cause and effect exist but require analysis or expertise to understand. Good practices (not best practices) exist because there may be multiple valid approaches. Approach: Sense-Analyze-Respond. Gather data, analyze using expert knowledge, and choose among valid options. This is the domain of expert analysis, engineering, and traditional research.

**Complex**: Cause and effect can only be deduced in retrospect. Emergent patterns arise from the interaction of many agents. No amount of analysis can predict outcomes reliably. Approach: Probe-Sense-Respond. Conduct safe-to-fail experiments, observe what emerges, amplify what works, and dampen what does not. This is the domain of innovation, organizational change, and many social systems.

**Chaotic**: No perceivable relationship between cause and effect. Immediate action is needed to establish order. Approach: Act-Sense-Respond. Take decisive action to stabilize the situation, then assess what has changed, then respond with further action. This is the domain of crises — there is no time for analysis.

**Disorder/Confusion**: The state of not knowing which domain you are in. The most dangerous state because people default to their comfort zone rather than matching their approach to the actual situation. The first step in disorder is to gather enough information to assign the situation to one of the other domains.

**Decision-making implications**: The critical insight is that different situations require fundamentally different approaches. Treating a complex problem as complicated (analyzing when you should be experimenting) or a complicated problem as clear (applying rules when expertise is needed) leads to failure. Assess the domain before choosing a method.

## OODA Loop

The OODA loop (Observe-Orient-Decide-Act), developed by military strategist Colonel John Boyd, is a framework for rapid decision-making in competitive and uncertain environments.

**Observe**: Gather information about the current situation from multiple sources. In research, observation includes: environmental scanning, data collection, monitoring indicators, and sensing changes. The quality and breadth of observation determines the quality of subsequent orientation.

**Orient**: The most critical and often underappreciated phase. Orient yourself to the situation by: analyzing the observations, synthesizing them with existing knowledge, applying cultural traditions and previous experience, filtering through genetic heritage and personal disposition, and considering multiple perspectives. Orientation is where mental models, biases, and cultural filters shape understanding. Boyd emphasized that the ability to rapidly reorient — to break old mental models and adopt new ones — is the key competitive advantage.

**Decide**: Select a course of action based on your orientation. In complex situations, this may involve choosing among multiple uncertain options. The decision should be the best available option given current understanding, not the optimal option (which may be unknowable). Boyd argued for implicit guidance and control — embedded decision rules that enable faster response than explicit deliberation.

**Act**: Execute the decision. Observe the results. The action changes the environment, creating new observations that begin the next cycle. The cycle is continuous and overlapping — observation does not stop while you are acting.

**Competitive advantage through tempo**: Boyd argued that the side that can cycle through OODA faster than its competitor gains a decisive advantage. Speed of orientation (breaking old mental models and forming new ones) is more important than speed of action. In research, this translates to: rapidly updating hypotheses as new evidence emerges, iterating between data collection and analysis rather than treating them as sequential phases, and being willing to abandon failing lines of inquiry.

**Application to research**: The OODA loop applies to adaptive research strategies. Observe the information environment. Orient by synthesizing findings with existing knowledge and frameworks. Decide on the next research action. Act by conducting the research. Then observe the results and orient again. Tight OODA loops prevent investment in unproductive research directions.

## Decision Matrices

Decision matrices (weighted scoring models) provide a systematic method for evaluating options against multiple criteria.

**Construction process**: (1) Define the options (alternatives) to be evaluated. (2) Identify evaluation criteria — the factors that matter for the decision. (3) Assign weights to each criterion reflecting its relative importance (weights should sum to 1.0 or 100%). (4) Score each option on each criterion using a consistent scale (e.g., 1-5 or 1-10). (5) Calculate the weighted score for each option (sum of weight x score across all criteria). (6) Rank options by total weighted score.

**Criteria selection**: Criteria should be: relevant (directly related to the decision objectives), independent (not redundant with other criteria), measurable (can be assessed even if subjectively), and complete (collectively covering all important factors). Use the MECE principle (Mutually Exclusive, Collectively Exhaustive) as a guide.

**Weighting methods**: Direct assignment (decision-maker assigns weights based on judgment). Pairwise comparison (compare each pair of criteria and derive weights from preferences — the AHP method). Swing weighting (consider the range of variation on each criterion and weight based on the significance of that range). Rank-order centroid (rank criteria by importance and calculate weights mathematically).

**Sensitivity analysis**: Test how the ranking changes as weights or scores are varied. Identify the criteria weights and scores to which the conclusion is most sensitive. If the top-ranked option changes with small perturbations, the result is fragile and requires careful interpretation. If the top-ranked option is robust across reasonable variations, the result is more reliable.

**Limitations**: Decision matrices impose a compensatory model — high performance on one criterion can offset low performance on another. This may not be appropriate when there are minimum thresholds (an option that fails on safety should not be selected regardless of other scores). Criteria independence is often violated in practice. Numerical precision can create false confidence in inherently subjective assessments.

## Expected Value Analysis

Expected value analysis quantifies decision options by weighting outcomes by their probability of occurrence.

**Basic calculation**: Expected Value = sum of (probability of each outcome x value of each outcome) across all possible outcomes. For example, if an investment has a 60% chance of returning $100,000 and a 40% chance of losing $50,000, EV = (0.6 x $100,000) + (0.4 x -$50,000) = $40,000.

**Decision trees**: Visual representation of sequential decisions under uncertainty. Nodes are decision points (squares) or chance events (circles). Branches represent options or outcomes with associated probabilities. Terminal nodes show final payoffs. Solve by backward induction — calculate expected values from the terminal nodes back to the initial decision, choosing the highest-EV option at each decision node.

**Expected utility vs. expected value**: Expected value assumes linear utility of money — but most people are risk-averse (the pain of losing $100 exceeds the pleasure of gaining $100). Expected utility theory uses a concave utility function to model risk aversion. Risk-neutral decisions maximize expected value; risk-averse decisions maximize expected utility, which may favor options with lower variance even at the cost of lower expected value.

**Value of information analysis**: How much should you invest in gathering additional information before making a decision? The expected value of perfect information (EVPI) is the difference between the expected value with perfect information and the expected value under uncertainty. This sets an upper bound on what you should pay for any information-gathering activity. The expected value of imperfect information (EVII) can be calculated for specific information sources with known accuracy.

**Application to research prioritization**: When deciding which research question to pursue, estimate: the probability of finding a useful answer, the value of the answer (for decision-making or knowledge), and the cost of the research. Expected value analysis helps prioritize research activities that offer the best return on investment of time and resources.

## Multi-Criteria Decision Analysis (MCDA)

MCDA provides a family of methods for evaluating options against multiple, potentially conflicting criteria — more sophisticated than simple decision matrices.

**Analytic Hierarchy Process (AHP)**: Developed by Thomas Saaty. Structure the decision hierarchically: goal at the top, criteria at the next level, sub-criteria below, and options at the bottom. Make pairwise comparisons at each level using a 1-9 scale (1 = equal importance, 9 = extreme importance). Calculate priority vectors from the comparison matrices. Check consistency (Consistency Ratio should be below 0.10). Synthesize local priorities into global priorities to rank options.

**TOPSIS (Technique for Order of Preference by Similarity to Ideal Solution)**: Define the ideal solution (best score on every criterion) and the negative-ideal solution (worst score on every criterion). Measure each option's geometric distance from both. The preferred option is closest to the ideal and farthest from the negative-ideal. TOPSIS handles quantitative criteria well and is computationally straightforward.

**ELECTRE**: A family of outranking methods that do not require full compensability (unlike weighted scoring). ELECTRE builds concordance and discordance indices to determine whether one option outranks another. The result is a partial ranking — some options may be incomparable. ELECTRE is appropriate when criteria are not fully compensatory (a failure on one criterion cannot be fully offset by excellence on another).

**PROMETHEE**: Preference Ranking Organization Method for Enrichment Evaluations. Uses preference functions for each criterion to handle different types of criteria (linear, step, Gaussian). Generates a net outranking flow for each option. PROMETHEE provides both complete and partial rankings and is particularly good at handling mixed criteria types.

**Choosing among MCDA methods**: AHP is intuitive and handles subjective judgments well but can be inconsistent with many criteria. TOPSIS is computationally efficient for quantitative criteria. ELECTRE and PROMETHEE handle non-compensability and are appropriate when minimum thresholds or absolute performance levels matter. The choice depends on the nature of the criteria, the number of options, and the stakeholder context.

## Delphi Method

The Delphi method is a structured process for eliciting and synthesizing expert judgment through iterative rounds of anonymous questionnaires and controlled feedback.

**Process**: (1) Select a panel of experts with relevant knowledge and diverse perspectives (typically 10-30 experts). (2) Develop a questionnaire asking experts to provide estimates, judgments, or forecasts for the questions of interest. Include space for reasoning and justifications. (3) Collect responses anonymously. (4) Compile results — typically presenting the median, interquartile range, and a summary of reasoning. (5) Share the compiled results with all panelists. (6) Ask panelists to revise their responses in light of the group results, particularly those whose initial responses were outside the interquartile range (they are asked to provide reasons or revise). (7) Repeat for 2-4 rounds until responses converge or stabilize.

**Key design features**: Anonymity prevents dominance by high-status individuals and reduces conformity pressure. Iteration with controlled feedback allows learning from others' reasoning without direct social pressure. Statistical group response (median, IQR) represents the panel's judgment without requiring consensus.

**When to use Delphi**: When relevant data is scarce or unreliable, when the question requires human judgment that cannot be modeled quantitatively, when the topic is contentious and face-to-face discussion might be unproductive, and when expert opinions need to be aggregated systematically. Common applications: technology forecasting, policy assessment, risk assessment, and prioritization exercises.

**Limitations**: Results are only as good as the panel — biased or unqualified experts produce biased results. The process is time-consuming (weeks to months). Convergence may reflect social desirability rather than genuine agreement. The anonymous format prevents the creative debate that face-to-face interaction can produce. Real-time Delphi (web-based platforms that allow continuous updating) addresses some timeliness concerns.

## Nominal Group Technique (NGT)

The Nominal Group Technique is a structured group decision-making process that balances individual thinking with group discussion.

**Process**: (1) Silent idea generation — each participant independently writes down ideas or solutions (5-10 minutes). (2) Round-robin sharing — each participant shares one idea per round, recorded on a visible display, without discussion. Continue until all ideas are listed. (3) Clarification — the group discusses each idea for understanding (not evaluation). Remove duplicates and combine related ideas. (4) Individual ranking — each participant independently ranks or votes on the ideas. (5) Tabulation — aggregate individual rankings to produce a group ranking.

**Advantages over unstructured discussion**: Prevents domination by vocal individuals. Ensures all participants contribute. Separates idea generation from evaluation (preventing premature criticism). Produces a quantifiable group decision. The silent generation phase prevents anchoring on the first ideas mentioned.

**When to use NGT**: When group members have diverse perspectives that need to be heard. When the topic is controversial and open discussion might be unproductive. When there is a power imbalance in the group. When you need a quick, structured decision from a group. When prioritization among multiple options is needed.

**Variations**: Modified NGT adds a second round of discussion after initial ranking to explore disagreements, followed by a second vote. Electronic NGT uses anonymous digital platforms for idea generation and voting, further reducing social pressure effects.

## Integrating Decision Frameworks

No single decision framework is universally applicable. Effective decision-making requires matching the framework to the context.

**Framework selection guide**: Use Cynefin first to characterize the decision context. For clear problems, apply established rules. For complicated problems, use decision matrices, MCDA, or expected value analysis. For complex problems, use OODA-style iterative experimentation, scenario analysis, or Delphi for collective intelligence. For chaotic situations, act first and analyze later.

**Combining frameworks**: Use scenario analysis to identify possible futures, then apply decision matrices or expected value analysis within each scenario to evaluate options. Use Delphi to estimate uncertain parameters that feed into expected value calculations. Use NGT to identify evaluation criteria that feed into MCDA.

**Common decision-making pathologies**: Analysis paralysis (gathering information indefinitely to avoid the discomfort of deciding under uncertainty). Premature closure (deciding too quickly before adequate analysis). Satisficing inappropriately (accepting the first adequate option when the stakes warrant optimizing). Groupthink (converging on a decision without genuine critical evaluation). Sunk cost persistence (continuing a course of action because of past investment rather than future prospects).
