---
framework: "Adversarial Thinking & Red Teaming"
version: "1.0"
domain: "Critical Thinking"
agent: "coda"
tags: ["red-team", "devils-advocacy", "pre-mortem", "alternative-futures", "adversarial-analysis"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

## Red Team Analysis

Red teaming is a structured approach to challenging plans, policies, assumptions, and conclusions by adopting an adversarial perspective. Originating in military and intelligence communities, red teaming has been adopted across government, corporate, and cybersecurity domains.

**Purpose of red teaming**: To identify vulnerabilities, blind spots, and flawed assumptions before they lead to failure. Red teams provide an independent, adversarial perspective that is difficult to achieve through internal review alone, because organizations develop institutional biases, shared assumptions, and cultural norms that inhibit self-criticism.

**Red team composition**: Effective red teams include members with diverse backgrounds, expertise, and cognitive styles. They should be organizationally independent from the team whose work they are reviewing — reporting to a different chain of command to prevent social pressure to conform. External red teamers bring fresh perspectives but may lack contextual knowledge; internal red teamers have context but may share institutional biases.

**Red team methodology**: (1) Understand the plan, analysis, or system to be challenged. (2) Identify the assumptions, both explicit and implicit. (3) Challenge each assumption — what if it is wrong? What are the consequences? (4) Identify vulnerabilities — where could things go wrong? How could an adversary exploit weaknesses? (5) Develop alternative scenarios — what are other plausible interpretations of the evidence or other plausible outcomes? (6) Report findings constructively — the goal is to strengthen the plan, not to embarrass the planning team.

**Red team outputs**: Specific, actionable findings with: the vulnerability or flaw identified, the evidence or reasoning supporting the finding, the potential consequences if the flaw is not addressed, and recommended mitigations. Avoid vague criticism — every finding should be supported by specific analysis.

**Organizational challenges**: Red teams face resistance because their work inherently criticizes others. Successful red team programs require: senior leadership support, organizational culture that values challenge, clear rules of engagement, constructive framing (strengthening rather than criticizing), and mechanisms for incorporating findings into decision-making.

## Devil's Advocacy

Devil's advocacy assigns an individual or group to argue against the prevailing view, consensus, or preferred course of action. Unlike red teaming (which is broader), devil's advocacy specifically challenges a particular conclusion or decision.

**Historical context**: The Catholic Church historically appointed an "advocatus diaboli" to argue against the canonization of a candidate for sainthood, ensuring that the case was thoroughly examined from all angles. The elimination of this role in 1983 was followed by a significant increase in canonizations — illustrating the value of institutionalized dissent.

**Effective devil's advocacy**: The advocate must build the strongest possible case against the prevailing view, not merely raise superficial objections. This requires: deep understanding of the prevailing position, genuine effort to find its weaknesses, presentation of alternative evidence and interpretations, and logical rigor in the counter-argument. The exercise fails if the advocate is not taken seriously or does not take the role seriously.

**When to use devil's advocacy**: Before making high-stakes decisions, when the group appears to be converging too quickly on a single view, when there is pressure (political, organizational, emotional) favoring a particular conclusion, and when the consequences of being wrong are severe. Devil's advocacy is a safeguard against groupthink and premature closure.

**Limitations**: Devil's advocacy can become performative — a ritualistic exercise that the group tolerates without genuinely engaging with the counter-arguments. It may also create an adversarial dynamic that undermines team cohesion. To be effective, the organization must create genuine incentives for quality challenge and genuine responsiveness to the challenge.

## Team A / Team B Analysis

Team A/Team B analysis assigns separate groups to independently analyze the same evidence and develop competing assessments. This technique was famously used in 1976 when the CIA's Team B provided an alternative assessment of Soviet strategic capabilities that challenged the CIA's official Team A estimate.

**Methodology**: Define the analytical question clearly. Provide both teams with the same evidence base. Teams develop their assessments independently, without communication during the analytical phase. Each team presents its assessment, including key judgments, supporting evidence, assumptions, and confidence levels. A senior panel or decision-maker evaluates both assessments.

**Advantages**: Forces explicit articulation of assumptions and reasoning. Demonstrates that the same evidence can support different conclusions (combating false certainty). Reveals the role of assumptions in driving analytical conclusions. Creates a natural structure for comparing alternative interpretations.

**Design considerations**: Teams should have comparable analytical capability and access to information. Differences in conclusions should stem from different assumptions or analytical approaches, not from information asymmetry. The technique works best when the question is genuinely ambiguous and reasonable people could disagree.

**Challenges**: Resource-intensive (requires two full analytical teams). May create competitive dynamics that prioritize "winning" over truth-seeking. The 1976 Team B exercise was later criticized for overestimating Soviet capabilities — demonstrating that alternative analysis is not inherently more accurate, just differently biased. The value lies in the comparison and the explicit articulation of assumptions, not in privileging one team's conclusion.

## Pre-Mortem Analysis

Pre-mortem analysis, developed by Gary Klein, asks participants to imagine that a plan has been implemented and has failed spectacularly, then work backward to identify what went wrong. This technique leverages prospective hindsight — the finding that people generate more reasons for an outcome when told it has already occurred than when asked to predict whether it will occur.

**Process**: (1) Describe the plan, project, or assessment in detail. (2) Ask each participant to imagine it is some time in the future and the plan has failed completely. (3) Each participant independently writes down all the reasons they can think of for the failure. (4) Go around the room, with each person sharing one reason per round (to prevent premature convergence). (5) Consolidate the list and identify the most significant and plausible failure modes. (6) Develop mitigations or contingency plans for the top failure modes.

**Psychological mechanism**: Pre-mortems work because they: overcome the planning fallacy (the tendency to be optimistic about plans we have committed to), give permission to express doubts (participants are explicitly asked to imagine failure rather than volunteering criticism), harness prospective hindsight (imagining an outcome as having already occurred improves the generation of causal explanations), and bypass groupthink (the exercise legitimizes dissent by making it a required task rather than an act of opposition).

**Variations**: "What if we are wrong?" analysis applies the same logic to analytical assessments rather than plans. The analyst imagines that their key judgment proved wrong six months later and identifies the most likely reasons. This surfaces hidden assumptions and identifies the evidence that would be most important to seek.

**Integration with project management**: Conduct pre-mortems at the beginning of major projects, after significant scope changes, and before final decisions. Use the results to update risk registers, develop monitoring indicators, and create contingency plans. Revisit the pre-mortem findings periodically to check whether identified risks are materializing.

## Alternative Futures Analysis

Alternative futures analysis develops multiple plausible scenarios for how a situation might evolve, rather than predicting a single most likely outcome. This is essential for strategic planning under uncertainty.

**Scenario development process**: (1) Define the focal question (what are we trying to understand?). (2) Identify the driving forces — the key factors that will shape the future (economic, technological, political, social, environmental). (3) Identify the critical uncertainties — the driving forces whose outcomes are most uncertain and most impactful. (4) Select two to three critical uncertainties as scenario axes. (5) Develop scenario logics — the combinations of uncertainty outcomes that create distinct futures. (6) Flesh out each scenario into a coherent narrative. (7) Identify implications for strategy and decision-making across scenarios.

**The 2x2 matrix method**: Select the two most critical uncertainties. Each has two possible outcomes (high/low, present/absent). The four combinations define four distinct scenarios. This is the most common approach (used by Shell, the Global Business Network, and many governments). Each scenario should be internally consistent, plausible, and sufficiently different from the others to span the space of possibilities.

**Cone of plausibility**: Visualize the future as a cone expanding from the present, with the width representing the range of plausible outcomes. Near-term futures are more constrained (smaller cone width) because many factors are already determined. Far-term futures are less constrained (wider cone). Some futures within the cone are more probable than others, but the entire cone should be considered in planning.

**Indicators and signposts**: For each scenario, identify early warning indicators — observable events or data points that would signal movement toward that scenario. Monitor these indicators continuously. This transforms scenarios from static thought exercises into dynamic early warning systems.

**Avoiding pitfalls**: Do not treat scenarios as predictions — they are tools for thinking about uncertainty, not forecasts. Do not privilege the "most likely" scenario to the exclusion of others — the purpose is to prepare for multiple futures. Ensure scenarios are genuinely different, not variations on a single theme. Include at least one scenario that challenges the organization's fundamental assumptions.

## High-Impact / Low-Probability Assessment

High-impact, low-probability (HILP) events — sometimes called black swans (Taleb) or strategic shocks — deserve analytical attention disproportionate to their assessed probability because their consequences can be catastrophic.

**Why HILP events are underestimated**: Availability heuristic (if we cannot easily recall similar events, we judge them as unlikely). Normalcy bias (we expect the future to resemble the recent past). Complexity (HILP events often arise from the interaction of multiple factors, each individually unlikely). Incentive structures (analysts and decision-makers are rewarded for being right about likely events and not penalized for failing to predict unlikely ones).

**Analytical approach**: (1) Generate a list of potential HILP events through brainstorming, red teaming, historical analogy, and expert consultation. Cast a wide net — the purpose is to surface possibilities, not to assess probability. (2) For each event, assess: probability (even if very low), impact (across multiple dimensions — strategic, financial, reputational, operational), velocity (how quickly would the impact unfold?), and warning time (how much advance notice would we have?). (3) Identify indicators that would provide early warning. (4) Develop contingency plans or response frameworks that could be activated rapidly.

**Historical precedent analysis**: Study past HILP events for patterns: 9/11, the 2008 financial crisis, COVID-19, the Arab Spring, Fukushima. Common features include: pre-event warnings that were available but not heeded, cascade failures (one failure triggering others), and systemic vulnerabilities that were known but not addressed because the triggering event was deemed unlikely.

**Communicating HILP assessments**: Decision-makers struggle with HILP events because they are, by definition, unlikely. Effective communication requires: concrete scenarios (not abstract probabilities), vivid impact descriptions, historical analogies, and actionable recommendations (what can be done now to prepare). Frame as insurance — we prepare not because we expect the event, but because the consequences of being unprepared are unacceptable.

## Contrarian Analysis Techniques

Contrarian analysis systematically challenges the prevailing wisdom and explores alternative interpretations.

**What if? analysis**: Select a key assumption or conventional wisdom and ask "what if the opposite were true?" or "what if this well-established fact changed?" Then rigorously explore the implications. This is not about being contrarian for its own sake but about stress-testing assumptions and expanding the range of considered possibilities.

**Linchpin analysis**: Identify the key assumptions, judgments, or factors upon which the entire assessment depends (the linchpins). Then assess: How confident are we in each linchpin? What would change if a linchpin proved wrong? Where are the linchpins most vulnerable? This technique focuses analytical effort on the most critical points of potential failure.

**Outside-in thinking**: Reverse the normal analytical direction. Instead of starting with what you know and building outward, start with the broadest possible set of outcomes and work inward to identify which are most and least likely. This prevents premature narrowing of the hypothesis space and ensures that unlikely but possible outcomes are considered.

**Structured self-critique**: At the end of an analytical process, systematically ask: What evidence did we not find that we would expect to find if our conclusion were correct? What alternative explanations did we not fully explore? What assumptions are we making that we have not tested? Where are we most uncertain, and how does that uncertainty affect our conclusions? What would change our minds?

## Integrating Adversarial Thinking into Research Practice

**Institutionalizing challenge**: Build adversarial thinking into standard operating procedures rather than treating it as an occasional exercise. Assign a "challenger" role in every analytical team meeting. Require documented consideration of alternative hypotheses in every assessment. Conduct pre-mortems for every major project or decision.

**Psychological safety**: Adversarial thinking only works if people feel safe challenging the prevailing view. Leaders must: model receptivity to challenge, reward quality dissent, protect dissenters from retaliation, and distinguish between the idea being challenged and the person who proposed it. Without psychological safety, adversarial techniques become empty rituals.

**Calibrating adversarial intensity**: Not every question requires full red team analysis. Match the intensity of challenge to the stakes: routine assessments may need only a brief "consider the opposite" exercise, while high-stakes decisions warrant formal red team or Team A/Team B analysis. Over-applying adversarial techniques wastes resources and creates analysis paralysis; under-applying them creates blind spots.

**Learning from failures**: When assessments prove wrong, conduct structured post-mortems to understand why. Was the failure due to: incorrect information, flawed assumptions, analytical errors, cognitive biases, or genuine unpredictability? Distinguish between good process with bad outcome (sometimes happens despite good analysis) and bad process that led to bad outcome (indicates systemic problems). Use post-mortem findings to improve future analytical practices.
