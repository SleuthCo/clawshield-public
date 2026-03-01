---
framework: "Testing"
version: "1.0"
domain: "Software Quality"
agent: "friday"
tags: ["testing", "unit-tests", "integration-tests", "contract-testing", "property-based", "mocks", "test-pyramid"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Testing Strategies

## Test Pyramid

The test pyramid is a model for structuring tests. It recommends many fast, isolated unit tests at the base; fewer integration tests in the middle; and very few end-to-end tests at the top.

**Unit tests (base):** Fast (milliseconds), isolated, deterministic. Test individual functions, methods, or classes. Mock external dependencies. Provide immediate feedback during development. Target: 70-80% of all tests.

**Integration tests (middle):** Test interactions between components: database queries against a real database, HTTP calls to a test server, message queue publish/consume. Slower (seconds) but verify real interactions. Target: 15-20% of all tests.

**End-to-end tests (top):** Test the full system from the user's perspective. Interact through the UI or public API. Slowest, most brittle, most expensive to maintain. Reserve for critical user journeys. Target: 5-10% of all tests.

**The testing trophy (alternative model):** Kent C. Dodds' model emphasizes integration tests as the sweet spot: they provide the best ratio of confidence to cost. Static analysis (linting, type checking) forms the base, followed by unit tests, integration tests, and E2E tests.

## Unit Testing Patterns

**Arrange-Act-Assert (AAA):** Structure every test in three phases.

```typescript
describe("PricingService", () => {
  it("applies bulk discount for orders over 100 units", () => {
    // Arrange
    const service = new PricingService(new BulkPricingStrategy());
    const items = [{ price: 10.0, quantity: 150 }];

    // Act
    const total = service.calculateTotal(items);

    // Assert
    expect(total).toBe(1275.0); // 150 * 10 * 0.85
  });
});
```

**One assertion per test (principle, not rigid rule):** Each test should verify one logical concept. Multiple `expect` calls are fine if they verify different aspects of the same behavior, but a test should not test two unrelated behaviors.

**Test naming conventions:**

- `should [expected behavior] when [condition]`
- `[method] returns [expected] given [input]`
- `[method] throws [error] when [condition]`

**Edge case checklist:** Null/undefined inputs, empty collections, boundary values (0, 1, MAX_INT), unicode strings, concurrent access, error responses.

**Testing pure functions:** Pure functions (no side effects, same input always gives same output) are the easiest to test. Design code to maximize pure functions; push side effects to the boundaries.

## Integration Testing

Integration tests verify that components work together. They use real dependencies (databases, caches, message brokers) rather than mocks.

**Test containers:** Use Docker containers to spin up real dependencies for tests. Testcontainers library supports many languages.

```typescript
import { PostgreSqlContainer } from "@testcontainers/postgresql";

describe("UserRepository", () => {
  let container: StartedPostgreSqlContainer;
  let repo: UserRepository;

  beforeAll(async () => {
    container = await new PostgreSqlContainer("postgres:16")
      .withDatabase("test")
      .start();
    const pool = new Pool({ connectionString: container.getConnectionUri() });
    await runMigrations(pool);
    repo = new UserRepository(pool);
  }, 30000);

  afterAll(async () => {
    await container.stop();
  });

  it("saves and retrieves a user", async () => {
    const user = { id: "usr_1", name: "Alice", email: "alice@example.com" };
    await repo.save(user);
    const found = await repo.findById("usr_1");
    expect(found).toEqual(user);
  });

  it("returns null for non-existent user", async () => {
    const found = await repo.findById("nonexistent");
    expect(found).toBeNull();
  });
});
```

**Database test patterns:**

- Run each test in a transaction that rolls back after the test (fast, isolated).
- Alternatively, truncate all tables between tests.
- Use unique test data per test to avoid interference.
- Test actual SQL queries, not just repository method signatures.

**API integration tests:**

```typescript
import request from "supertest";

describe("POST /api/orders", () => {
  it("creates an order and returns 201", async () => {
    const response = await request(app)
      .post("/api/orders")
      .set("Authorization", `Bearer ${testToken}`)
      .send({ items: [{ productId: "prod_1", quantity: 2 }] })
      .expect(201);

    expect(response.body.order.id).toBeDefined();
    expect(response.body.order.status).toBe("pending");
  });

  it("returns 400 for empty items", async () => {
    const response = await request(app)
      .post("/api/orders")
      .set("Authorization", `Bearer ${testToken}`)
      .send({ items: [] })
      .expect(400);

    expect(response.body.error.code).toBe("VALIDATION_ERROR");
  });
});
```

## Contract Testing (Pact)

Contract testing verifies that a provider (API) and consumer (client) agree on the API contract. It catches breaking changes before deployment.

**Consumer-driven contracts:** The consumer defines what it expects from the provider. The provider verifies that it satisfies those expectations.

```typescript
// Consumer side: define expectations
const interaction = {
  state: "a user with ID usr_1 exists",
  uponReceiving: "a request for user usr_1",
  withRequest: {
    method: "GET",
    path: "/api/users/usr_1",
    headers: { Accept: "application/json" },
  },
  willRespondWith: {
    status: 200,
    headers: { "Content-Type": "application/json" },
    body: {
      id: like("usr_1"),
      name: like("Alice"),
      email: like("alice@example.com"),
    },
  },
};
```

```typescript
// Provider side: verify contract
const verifier = new Verifier({
  providerBaseUrl: "http://localhost:3000",
  pactUrls: ["./pacts/consumer-provider.json"],
  stateHandlers: {
    "a user with ID usr_1 exists": async () => {
      await seedUser({ id: "usr_1", name: "Alice", email: "alice@example.com" });
    },
  },
});
await verifier.verifyProvider();
```

**Pact Broker:** A central service that stores and shares contracts. The provider can verify against all consumer contracts. The broker also provides "can-i-deploy" checks that verify whether a version is compatible with all its consumers before deployment.

## E2E Testing

End-to-end tests validate the entire system from the user's perspective. They are expensive to write and maintain, so reserve them for critical user journeys.

**Tools:** Playwright (recommended for web), Cypress, Selenium. For API-only E2E tests, use HTTP client libraries or tools like k6.

**Best practices:**

- Test critical paths only: sign up, log in, core business workflow, payment.
- Use stable selectors (data-testid attributes) rather than CSS selectors or XPath.
- Seed test data through the API, not the UI, to speed up setup.
- Implement retry logic for flaky UI interactions.
- Run in isolated environments with known data.
- Treat E2E test failures as high priority: a flaky E2E test is worse than no test.

## Property-Based Testing

Property-based testing generates random inputs and verifies that properties (invariants) hold for all inputs. It finds edge cases that example-based tests miss.

```typescript
import fc from "fast-check";

describe("sort", () => {
  it("returns an array of the same length", () => {
    fc.assert(
      fc.property(fc.array(fc.integer()), (arr) => {
        const sorted = mySort([...arr]);
        return sorted.length === arr.length;
      })
    );
  });

  it("returns elements in non-decreasing order", () => {
    fc.assert(
      fc.property(fc.array(fc.integer()), (arr) => {
        const sorted = mySort([...arr]);
        for (let i = 1; i < sorted.length; i++) {
          if (sorted[i] < sorted[i - 1]) return false;
        }
        return true;
      })
    );
  });

  it("is idempotent", () => {
    fc.assert(
      fc.property(fc.array(fc.integer()), (arr) => {
        const once = mySort([...arr]);
        const twice = mySort([...once]);
        return JSON.stringify(once) === JSON.stringify(twice);
      })
    );
  });
});
```

**Common properties to test:** Roundtrip (encode/decode), idempotency (f(f(x)) === f(x)), invariants (length, sum, membership), commutativity, associativity.

**Libraries:** fast-check (TypeScript/JavaScript), Hypothesis (Python), QuickCheck (Haskell), proptest (Rust), rapid (Go).

## Mutation Testing

Mutation testing measures test quality by introducing small changes (mutations) to the code and checking whether tests catch them. If a mutation is not detected (survives), the tests are insufficient.

**Common mutations:** Replace `>` with `>=`, negate conditions, remove method calls, change return values, swap arithmetic operators.

**Interpreting results:** Mutation score = killed mutants / total mutants. A high mutation score (> 80%) indicates thorough tests. Focus on surviving mutants in critical business logic.

**Tools:** Stryker (TypeScript/JavaScript), mutmut (Python), cargo-mutants (Rust), go-mutesting (Go).

## Test Doubles

Test doubles replace real dependencies in tests. Understanding the types prevents misuse.

**Dummy:** Passed around but never used. Fills a required parameter. A null logger, for example.

**Stub:** Returns predetermined responses. Does not verify interactions. Use when you need to control the dependency's output.

```typescript
const userStub: UserRepository = {
  findById: async (id: string) => ({ id, name: "Test User", email: "test@example.com" }),
  save: async () => {},
  findAll: async () => [],
  delete: async () => {},
};
```

**Spy:** Records calls for later verification. Use when you need to verify that a dependency was called correctly.

```typescript
const notifierSpy = {
  calls: [] as any[],
  send: async (to: string, msg: string) => {
    notifierSpy.calls.push({ to, msg });
  },
};

await service.processOrder(order);
expect(notifierSpy.calls).toHaveLength(1);
expect(notifierSpy.calls[0].to).toBe(order.customerEmail);
```

**Mock:** Like a spy but with pre-programmed expectations. Verifies that specific interactions occurred. Overuse of mocks leads to brittle, tightly-coupled tests.

**Fake:** A working implementation with shortcuts. An in-memory database, a local file system instead of S3, a fake SMTP server. Fakes test more realistically than stubs but require maintenance.

**When to use what:**

- Use stubs to control inputs.
- Use spies to verify outputs to dependencies.
- Use fakes for complex dependencies where behavior matters.
- Use mocks sparingly; prefer stubs and spies for most cases.
- Never mock what you do not own (third-party libraries). Wrap third-party libraries in your own interface and mock that interface.
