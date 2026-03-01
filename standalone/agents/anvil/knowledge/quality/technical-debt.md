---
framework: "Technical Debt"
version: "1.0"
domain: "Software Quality"
agent: "friday"
tags: ["technical-debt", "refactoring", "architecture-fitness", "code-quality", "prioritization"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Technical Debt Management

## Identifying Technical Debt

Technical debt is the implied cost of future rework caused by choosing an expedient solution now instead of a better approach that would take longer. Not all shortcuts are debt; debt is only meaningful when it has carrying costs (slows future development, increases risk, or incurs operational overhead).

**Symptoms of technical debt:**

- **Slow feature delivery:** Simple features take disproportionately long because they require working around existing code.
- **High defect rate:** Bugs keep appearing in the same areas of the codebase.
- **Difficult onboarding:** New team members take weeks to become productive because the code is hard to understand.
- **Deployment fear:** The team avoids deploying because deployments frequently cause incidents.
- **Copy-paste code:** The same logic appears in multiple places with slight variations.
- **Long build times:** Build and test cycles are slow due to tight coupling and large monolithic builds.
- **Outdated dependencies:** Dependencies are multiple major versions behind, making upgrades increasingly difficult and risky.

**Code-level indicators:** High cyclomatic complexity (functions with many branches), long functions (> 50 lines), large classes (> 500 lines), deep nesting (> 3 levels), high coupling between modules, low cohesion within modules.

**Architecture-level indicators:** Circular dependencies between modules, shared mutable state, tight coupling between services, lack of clear boundaries, inconsistent patterns across the codebase.

## Debt Quadrants

Martin Fowler's technical debt quadrant categorizes debt along two axes: reckless vs. prudent, and deliberate vs. inadvertent.

**Reckless and deliberate:** "We don't have time for design." The team knowingly takes shortcuts without planning to address them. This is the most dangerous form because it accumulates rapidly and is often not tracked.

**Reckless and inadvertent:** "What's layering?" The team doesn't know enough to recognize they are creating debt. Common with inexperienced teams or teams working in unfamiliar domains. Addressed through mentoring, code review, and education.

**Prudent and deliberate:** "We must ship now and will deal with the consequences." A conscious decision to take on debt with a plan to repay it. Acceptable when the trade-off is well understood and the debt is tracked. Example: using a simpler data model for an MVP with a plan to redesign before scaling.

**Prudent and inadvertent:** "Now we know how we should have done it." The team learned something through building that they could not have known beforehand. Natural and unavoidable. Address through refactoring once the better approach is understood.

**Key insight:** Prudent deliberate debt is a valid business tool when managed intentionally. Reckless debt (either form) is a liability. Inadvertent debt is inevitable and should be addressed through continuous improvement.

## Prioritization Frameworks

Not all technical debt is worth repaying. Prioritize based on impact and cost.

**Impact vs. effort matrix:**

- **High impact, low effort (quick wins):** Fix immediately. Outdated logging format, missing indexes, confusing variable names.
- **High impact, high effort (strategic):** Plan as dedicated projects. Service decomposition, database migration, framework upgrade.
- **Low impact, low effort (nice to have):** Address opportunistically. Code style inconsistencies, minor dead code.
- **Low impact, high effort (avoid):** Do not invest. Rewriting a working system that nobody touches.

**Cost of delay:** How much does this debt cost per week/month? If a piece of debt costs 4 developer-hours per week in workarounds and takes 40 hours to fix, it pays for itself in 10 weeks. Compare this payback period to other investments.

**Frequency-weighted prioritization:** Debt in frequently modified code has higher carrying costs than debt in stable, rarely-touched code. Use version control data (number of commits, number of distinct authors) to identify high-churn files. Focus debt reduction on high-churn areas.

**Risk-based prioritization:** Some debt increases the risk of incidents, security vulnerabilities, or data loss. Prioritize debt that affects production reliability or security, regardless of its development impact.

**Tech debt backlog:** Maintain a visible, prioritized backlog of technical debt items. Include estimated cost (effort to fix), estimated value (time saved per sprint, risk reduction), and affected area. Review quarterly.

## Refactoring Strategies

Refactoring is the disciplined practice of restructuring existing code without changing its external behavior. It is the primary tool for reducing technical debt.

**Incremental refactoring (preferred):** Make small, safe changes alongside feature work. Improve the code you touch. Each change is small enough to be confident in its correctness. No dedicated "refactoring sprints" needed.

**Strangler pattern for large refactoring:** When replacing a subsystem, build the new implementation alongside the old one. Gradually route traffic/calls to the new implementation. Remove the old implementation when it handles no traffic. This avoids big-bang rewrites.

**Branch by abstraction:** Introduce an abstraction layer (interface) in front of the code you want to replace. Implement the new version behind the same interface. Switch to the new implementation behind the abstraction. Remove the old implementation and the abstraction.

**Parallel implementation:** For critical algorithms or data stores, run the old and new implementations side by side, comparing results. This validates correctness before switching.

**Common refactoring techniques:**

- **Extract function:** Break a long function into smaller, well-named functions.
- **Inline function:** If a function's body is as clear as its name, inline it.
- **Extract class:** Split a large class into multiple cohesive classes.
- **Move method:** Move a method to the class that uses its data most.
- **Replace conditional with polymorphism:** Replace switch/if-else chains with the Strategy pattern.
- **Introduce parameter object:** Replace a long parameter list with a single object.
- **Replace magic numbers/strings with named constants:** `MAX_RETRY_ATTEMPTS = 3` instead of `3`.

**Safe refactoring checklist:**

1. Ensure comprehensive test coverage before refactoring.
2. Make one small change at a time.
3. Run tests after each change.
4. Commit frequently (each small, verified change is a commit).
5. If tests break, revert the last change rather than debugging forward.

## Boy Scout Rule

"Leave the campground cleaner than you found it." When you modify a file, improve it slightly: rename a confusing variable, extract a duplicated block, add a missing test, update an outdated comment.

**Scope:** The improvement should be small and low-risk. If the improvement requires significant changes, create a separate ticket rather than mixing it with feature work.

**Tracking:** Some teams track Boy Scout improvements in commit messages or PR labels to make the practice visible and celebrate it.

**Limitations:** Boy Scout rule works well for incremental improvements. It is insufficient for structural debt (architecture changes, database migrations, major dependency upgrades). Those require deliberate, planned effort.

## Architecture Fitness Functions

Fitness functions are automated checks that verify architectural characteristics remain within acceptable bounds. They make non-functional requirements testable and prevent architectural drift.

**Performance fitness functions:**

```typescript
// API response time remains under budget
test("GET /api/users responds within 200ms", async () => {
  const start = performance.now();
  await request(app).get("/api/users").expect(200);
  const duration = performance.now() - start;
  expect(duration).toBeLessThan(200);
});
```

**Dependency fitness functions:**

```typescript
// No circular dependencies between modules
import { analyzeModuleDependencies } from "./arch-tools";

test("no circular dependencies", () => {
  const cycles = analyzeModuleDependencies("./src");
  expect(cycles).toHaveLength(0);
});

// Core domain does not depend on infrastructure
test("domain layer does not import from infrastructure", () => {
  const imports = getImportsFrom("./src/domain");
  const infraImports = imports.filter(i => i.includes("/infrastructure/"));
  expect(infraImports).toHaveLength(0);
});
```

**Coupling fitness functions:**

- Monitor the number of cross-module dependencies. Alert when it exceeds a threshold.
- Track the afferent (incoming) and efferent (outgoing) coupling of each module. High afferent coupling means the module is widely used (stable); high efferent coupling means it depends on many things (unstable).

**ArchUnit (Java/Kotlin) / archunit-ts (TypeScript) / import-linter (Python):** Dedicated tools for expressing architectural rules as tests.

```python
# import-linter configuration (.importlinter)
[importlinter]
root_packages = myapp

[importlinter:contract:1]
name = Domain does not import infrastructure
type = forbidden
source_modules = myapp.domain
forbidden_modules = myapp.infrastructure

[importlinter:contract:2]
name = No circular imports
type = independence
modules =
    myapp.domain
    myapp.infrastructure
    myapp.api
```

**Complexity fitness functions:** Track cyclomatic complexity of new code. Fail CI if any new function exceeds a complexity threshold (e.g., 15). Track overall complexity trends.

**Dependency freshness:** Track how many dependency versions behind the project is. Alert when any dependency is more than two major versions behind its latest release.

## Communicating Technical Debt to Stakeholders

Technical teams often struggle to justify debt reduction to non-technical stakeholders. Frame debt in business terms.

**Translate to business impact:**

- "We have technical debt in the payment system" becomes "Implementing a new payment method takes 3 weeks instead of 3 days because of how the payment system is structured."
- "We need to refactor the user module" becomes "We are spending 30% of each sprint working around limitations in the user module instead of building new features."

**Use data:**

- Track time spent on bug fixes vs. features over time. Increasing bug-fix time is a symptom of accumulating debt.
- Measure lead time for changes. If lead time is increasing, debt is likely a contributing factor.
- Track incident frequency in debt-heavy areas. Connect incidents to business cost (downtime, lost revenue, customer trust).

**The 20% rule:** Allocate approximately 20% of engineering capacity to debt reduction. This maintains a sustainable pace of debt repayment without stopping feature delivery. Adjust the ratio based on debt severity.

**Debt visibility:** Make debt visible in project management tools. Tag tickets as "tech debt." Report debt reduction progress alongside feature delivery in sprint reviews.
