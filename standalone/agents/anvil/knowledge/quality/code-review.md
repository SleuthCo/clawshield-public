---
framework: "Code Review"
version: "1.0"
domain: "Software Quality"
agent: "friday"
tags: ["code-review", "pull-requests", "feedback", "review-checklist", "best-practices"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Code Review Best Practices

## Purpose of Code Review

Code review serves multiple purposes beyond finding bugs. It distributes knowledge across the team, maintains consistency, mentors junior developers, and catches architectural issues early.

**Primary goals:**

- **Correctness:** Does the code do what it is supposed to? Are edge cases handled?
- **Clarity:** Can another developer understand this code six months from now?
- **Maintainability:** Is the code easy to modify, extend, and debug?
- **Security:** Are there vulnerabilities, injection risks, or data exposure?
- **Consistency:** Does the code follow the team's conventions and patterns?

**What code review is not:** A gatekeeping exercise. A place to enforce personal style preferences. A power dynamic. An excuse to delay merging.

## Review Checklists

### Correctness Checklist

- Does the code correctly implement the requirements or fix the described bug?
- Are all edge cases handled (null, empty, negative, overflow, concurrent access)?
- Are error paths handled gracefully? Are errors logged with sufficient context?
- Are resources properly cleaned up (connections closed, files closed, listeners removed)?
- Is the code idempotent where it needs to be (API handlers, message consumers)?
- Are there race conditions in concurrent code?
- Are transactions used correctly (proper isolation level, proper scope)?

### Security Checklist

- Is user input validated and sanitized before use?
- Are queries parameterized (no string interpolation in SQL)?
- Are secrets hard-coded or logged?
- Are authentication and authorization checks in place?
- Is sensitive data properly encrypted at rest and in transit?
- Are error messages exposing internal details to end users?
- Are dependencies up to date and free of known vulnerabilities?

### Design Checklist

- Does the change follow the Single Responsibility Principle?
- Are there appropriate abstractions, or is the code too concrete or too abstract?
- Is there code duplication that should be extracted?
- Are public APIs well-named and well-documented?
- Would a new team member understand the design decisions? Are non-obvious decisions documented with comments?
- Is the code testable? Can dependencies be substituted for tests?

### Performance Checklist

- Are there N+1 query patterns?
- Are large datasets loaded into memory unnecessarily?
- Are there missing database indexes for new queries?
- Is caching used where appropriate, and is cache invalidation correct?
- Are there potential memory leaks (event listeners, closures, global references)?

## LGTM Criteria

Define what "Looks Good To Me" means for your team. A reviewer should approve when:

1. The code is correct and handles edge cases.
2. The code is readable and follows team conventions.
3. Tests are adequate (new code has tests, changed code has updated tests).
4. No significant security concerns.
5. The PR description explains the context and motivation.

**Approval does not mean perfect.** It means "this is good enough to ship and I have no blocking concerns." Minor nits can be addressed in follow-up PRs.

**Two-approver policy:** For critical systems (payment, auth, data migrations), require two reviewers from different team members. One reviewer focuses on correctness, the other on architecture and security.

## Automated Review Tools

Automate everything that can be automated to free human reviewers for higher-level concerns.

**Linting and formatting:** eslint, prettier, ruff, gofmt, rustfmt. Run in CI. Auto-fix where possible. Never argue about formatting in code review; let the tool decide.

**Static analysis:** SonarQube, CodeClimate, Semgrep, CodeQL. Flag complexity, duplication, and security issues automatically.

**Type checking:** TypeScript's `tsc --noEmit`, mypy, pyright. Catch type errors before review.

**Test coverage:** Report coverage changes in the PR. Flag if coverage decreases significantly.

**Dependency analysis:** Dependabot, Renovate. Auto-create PRs for dependency updates.

**AI-assisted review:** GitHub Copilot for PRs, CodeRabbit, Sourcery. Use as a first pass to catch common issues, but do not replace human review for design and architecture concerns.

## PR Size Guidelines

Small PRs are reviewed faster, reviewed more thoroughly, have fewer bugs, and are easier to revert.

**Size targets:**

- **Ideal:** Under 200 lines of changed code (excluding tests and generated files).
- **Acceptable:** 200-400 lines.
- **Too large:** Over 400 lines. Split into smaller PRs.

**Splitting strategies:**

- **Vertical slicing:** Ship a thin, complete feature (one endpoint, one UI component) rather than all endpoints without any UI.
- **Preparatory refactoring:** Extract refactoring into a separate PR before adding new features.
- **Feature flags:** Ship incomplete features behind flags. Each PR adds a piece of the feature.
- **Data migration separate from code:** Apply database migration in one PR, deploy the code that uses it in another.
- **Interface first:** Define the interface/API in one PR. Implement it in the next.

**Stacked PRs:** For large features, create a chain of dependent PRs. Each PR builds on the previous one. Tools: ghstack, Graphite, git-branchless. Review and merge sequentially.

## Architectural Review vs Implementation Review

Not all code reviews are the same. Distinguish between reviews that assess design decisions and reviews that assess implementation quality.

**Architectural review (design review):**

- Should happen before significant coding begins, not after.
- Reviews the approach: data model, API design, service boundaries, patterns used.
- Produces a design document or ADR (Architecture Decision Record) that is reviewed.
- Participants: senior engineers, architects, relevant domain experts.
- Questions to ask: "Will this approach scale?" "What are the failure modes?" "What alternatives were considered and why were they rejected?"

**Implementation review:**

- Standard PR review for merged code.
- Reviews the execution: code quality, tests, error handling, naming.
- Participants: any team member, ideally someone unfamiliar with the code.
- Questions to ask: "Is this correct?" "Is this clear?" "Is this tested?"

**Anti-pattern:** Discovering fundamental design issues during an implementation review of a 2000-line PR. At that point, the author has invested significant effort, and requesting a redesign is costly and demoralizing. Catch design issues early through upfront design reviews.

## Giving Constructive Feedback

**Be kind, be clear, be specific.** Code review is a conversation between colleagues, not a competition.

**Feedback principles:**

- **Comment on the code, not the person.** "This function is hard to follow" not "You wrote confusing code."
- **Ask questions rather than making demands.** "What happens if `items` is empty here?" is better than "You forgot to handle empty items."
- **Explain the why, not just the what.** "Consider using a Map instead of an object because lookups are O(1) and it handles non-string keys" is better than "Use a Map."
- **Distinguish between blocking and non-blocking feedback.** Prefix with `nit:` for non-blocking suggestions, `question:` for clarification, `suggestion:` for optional improvements. Make it clear what must be changed before approval.
- **Acknowledge good work.** When you see a clever solution, a well-written test, or a clean refactoring, say so. Positive feedback reinforces good practices.

**Comment examples:**

```
// Good
nit: This variable name `d` is cryptic. Consider `durationMs` for clarity.

// Good
question: This catches all exceptions silently. Was that intentional? I'm concerned
that unexpected errors (like network failures) would be swallowed.

// Good
suggestion: If we extract this into a separate function, we could reuse it in
the batch processing endpoint too. Not blocking this PR though.

// Bad
This is wrong. Fix it.

// Bad
Why didn't you use X pattern here? It's obviously better.
```

**Author responsibilities:**

- Write a clear PR description explaining what, why, and how to test.
- Self-review before requesting review (read your own diff).
- Respond to all comments, even if just acknowledging them.
- Do not take feedback personally. The reviewer is trying to improve the code, not criticize you.
- If you disagree, explain your reasoning. Seek a third opinion if needed.

**Reviewer responsibilities:**

- Review promptly (within 4-8 working hours). Delayed reviews block the author and incentivize large, batched PRs.
- Review thoroughly but pragmatically. Do not block on minor style preferences.
- Test the code if the change is complex or high-risk. Check out the branch and run it.
- Approve promptly when concerns are addressed. Do not require multiple re-review cycles for minor changes.

## Review Workflow Optimization

**Review turnaround time:** Track the time between PR opened and first review. Target under 4 hours during working hours. Long review times kill team velocity and morale.

**Review assignment:** Rotate reviewers across the team. Avoid having one person review all PRs (bus factor). Use CODEOWNERS for domain-specific review requirements.

**Draft PRs:** Use draft PRs for early feedback on approach before the code is complete. This catches design issues early without committing to a formal review.

**Review by reading order:** Start with the PR description, then tests (to understand intent), then implementation. This gives you context before diving into code.
