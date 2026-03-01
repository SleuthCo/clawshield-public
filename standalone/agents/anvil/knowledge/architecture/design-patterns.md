---
framework: "Design Patterns"
version: "1.0"
domain: "Software Architecture"
agent: "friday"
tags: ["design-patterns", "gof", "strategy", "observer", "repository", "factory", "anti-patterns"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Design Patterns in Modern Systems

## Strategy Pattern

Strategy encapsulates a family of algorithms behind a common interface, allowing them to be swapped at runtime. Prefer it over long switch/if-else chains.

**When to use:** Multiple algorithms for the same operation, algorithm selection at runtime, eliminating conditional logic for behavior variations.

```typescript
interface PricingStrategy {
  calculate(basePrice: number, quantity: number): number;
}

class RegularPricing implements PricingStrategy {
  calculate(basePrice: number, quantity: number): number {
    return basePrice * quantity;
  }
}

class BulkPricing implements PricingStrategy {
  calculate(basePrice: number, quantity: number): number {
    const discount = quantity > 100 ? 0.15 : quantity > 50 ? 0.10 : 0;
    return basePrice * quantity * (1 - discount);
  }
}

class SubscriptionPricing implements PricingStrategy {
  constructor(private discountRate: number) {}
  calculate(basePrice: number, quantity: number): number {
    return basePrice * quantity * (1 - this.discountRate);
  }
}

class OrderProcessor {
  constructor(private pricing: PricingStrategy) {}

  setPricing(strategy: PricingStrategy): void {
    this.pricing = strategy;
  }

  processOrder(items: { price: number; qty: number }[]): number {
    return items.reduce((total, item) =>
      total + this.pricing.calculate(item.price, item.qty), 0);
  }
}
```

**Anti-pattern:** Creating a strategy for only one algorithm with no foreseeable variations. Use a simple function instead.

## Observer Pattern

Observer defines a one-to-many dependency so that when one object changes state, all dependents are notified. In modern systems this manifests as event emitters, pub/sub, and reactive streams.

**When to use:** Decoupling producers from consumers, event-driven systems, UI state management, audit logging.

```typescript
type EventMap = {
  userCreated: { userId: string; email: string };
  orderPlaced: { orderId: string; total: number };
  error: { message: string; code: number };
};

class TypedEventEmitter<T extends Record<string, any>> {
  private listeners = new Map<keyof T, Set<Function>>();

  on<K extends keyof T>(event: K, handler: (payload: T[K]) => void): () => void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(handler);
    return () => this.listeners.get(event)?.delete(handler);
  }

  emit<K extends keyof T>(event: K, payload: T[K]): void {
    this.listeners.get(event)?.forEach(handler => handler(payload));
  }
}
```

**Anti-pattern:** Deep observer chains creating cascading updates. Limit event propagation depth; consider event sourcing for complex flows.

## Builder Pattern

Builder separates object construction from representation, enabling step-by-step creation of complex objects. Especially useful when constructors would have many parameters.

**When to use:** Objects with many optional parameters, constructing immutable objects, building test fixtures, query construction.

```typescript
class QueryBuilder {
  private table = "";
  private conditions: string[] = [];
  private orderFields: string[] = [];
  private limitValue?: number;
  private offsetValue?: number;

  from(table: string): this { this.table = table; return this; }

  where(condition: string): this {
    this.conditions.push(condition);
    return this;
  }

  orderBy(field: string, direction: "ASC" | "DESC" = "ASC"): this {
    this.orderFields.push(`${field} ${direction}`);
    return this;
  }

  limit(n: number): this { this.limitValue = n; return this; }
  offset(n: number): this { this.offsetValue = n; return this; }

  build(): string {
    if (!this.table) throw new Error("Table is required");
    let query = `SELECT * FROM ${this.table}`;
    if (this.conditions.length) query += ` WHERE ${this.conditions.join(" AND ")}`;
    if (this.orderFields.length) query += ` ORDER BY ${this.orderFields.join(", ")}`;
    if (this.limitValue !== undefined) query += ` LIMIT ${this.limitValue}`;
    if (this.offsetValue !== undefined) query += ` OFFSET ${this.offsetValue}`;
    return query;
  }
}
```

## Factory Pattern

Factory Method and Abstract Factory encapsulate object creation, enabling polymorphic instantiation without coupling to concrete classes.

**When to use:** Object creation depends on configuration or environment, supporting multiple implementations of the same interface, creating families of related objects.

```typescript
interface Logger {
  log(message: string): void;
}

function createLogger(env: string): Logger {
  switch (env) {
    case "development": return new ConsoleLogger();
    case "production": return new StructuredLogger();
    case "test": return new FileLogger();
    default: return new ConsoleLogger();
  }
}

// Abstract Factory for database connections
interface DatabaseFactory {
  createConnection(): Connection;
  createQueryBuilder(): QueryBuilder;
  createMigrator(): Migrator;
}

class PostgresFactory implements DatabaseFactory {
  createConnection(): Connection { return new PgConnection(); }
  createQueryBuilder(): QueryBuilder { return new PgQueryBuilder(); }
  createMigrator(): Migrator { return new PgMigrator(); }
}
```

**Anti-pattern:** Using factories for simple objects with no polymorphic behavior. A factory that always returns the same type adds indirection without benefit.

## Adapter Pattern

Adapter converts the interface of a class into another interface that clients expect. It enables classes with incompatible interfaces to work together.

**When to use:** Integrating third-party libraries, legacy code migration, standardizing interfaces across multiple implementations.

```typescript
interface PaymentGateway {
  charge(amount: number, currency: string, token: string): Promise<PaymentResult>;
  refund(transactionId: string, amount: number): Promise<RefundResult>;
}

class StripeAdapter implements PaymentGateway {
  constructor(private stripe: StripeSDK) {}

  async charge(amount: number, currency: string, token: string): Promise<PaymentResult> {
    const intent = await this.stripe.paymentIntents.create({
      amount: Math.round(amount * 100), // Stripe uses cents
      currency,
      payment_method: token,
      confirm: true,
    });
    return {
      transactionId: intent.id,
      status: intent.status === "succeeded" ? "success" : "failed",
    };
  }

  async refund(transactionId: string, amount: number): Promise<RefundResult> {
    const refund = await this.stripe.refunds.create({
      payment_intent: transactionId,
      amount: Math.round(amount * 100),
    });
    return { refundId: refund.id, status: refund.status };
  }
}
```

## Decorator Pattern

Decorator attaches additional responsibilities to an object dynamically. It provides a flexible alternative to subclassing for extending functionality.

**When to use:** Adding cross-cutting concerns (logging, caching, retries, metrics), layering behavior without modifying existing code.

```typescript
function withRetry<T>(fn: () => Promise<T>, maxRetries = 3): () => Promise<T> {
  return async () => {
    for (let i = 0; i < maxRetries; i++) {
      try {
        return await fn();
      } catch (err) {
        if (i === maxRetries - 1) throw err;
        await sleep(Math.pow(2, i) * 1000);
      }
    }
    throw new Error("Unreachable");
  };
}

function withCache<T>(fn: (key: string) => Promise<T>, ttlMs: number) {
  const cache = new Map<string, { value: T; expires: number }>();
  return async (key: string): Promise<T> => {
    const cached = cache.get(key);
    if (cached && cached.expires > Date.now()) return cached.value;
    const value = await fn(key);
    cache.set(key, { value, expires: Date.now() + ttlMs });
    return value;
  };
}

// Interface-based decorator for class composition
interface NotificationService {
  send(to: string, message: string): Promise<void>;
}

class LoggingNotificationService implements NotificationService {
  constructor(
    private inner: NotificationService,
    private logger: Logger,
  ) {}

  async send(to: string, message: string): Promise<void> {
    this.logger.info(`Sending notification to ${to}`);
    await this.inner.send(to, message);
    this.logger.info(`Notification sent to ${to}`);
  }
}
```

## Command Pattern

Command encapsulates a request as an object, enabling parameterization of operations, queuing, logging, and undo functionality.

**When to use:** Undo/redo systems, task queues, macro recording, transaction logging, decoupling request sender from executor.

```typescript
interface Command {
  execute(): Promise<void>;
  undo(): Promise<void>;
}

class TransferCommand implements Command {
  constructor(
    private from: Account,
    private to: Account,
    private amount: number,
  ) {}

  async execute(): Promise<void> {
    await this.from.debit(this.amount);
    await this.to.credit(this.amount);
  }

  async undo(): Promise<void> {
    await this.to.debit(this.amount);
    await this.from.credit(this.amount);
  }
}

class CommandHistory {
  private history: Command[] = [];

  async execute(command: Command): Promise<void> {
    await command.execute();
    this.history.push(command);
  }

  async undoLast(): Promise<void> {
    const command = this.history.pop();
    if (command) await command.undo();
  }
}
```

## Repository Pattern

Repository mediates between the domain and data mapping layers, providing a collection-like interface for accessing domain objects. It abstracts persistence mechanics from business logic.

**When to use:** Separating domain logic from data access, enabling testing with in-memory stores, supporting multiple storage backends.

```typescript
interface Repository<T extends { id: string }> {
  findById(id: string): Promise<T | null>;
  findAll(filter?: Partial<T>): Promise<T[]>;
  save(entity: T): Promise<void>;
  delete(id: string): Promise<void>;
}

class PostgresUserRepository implements Repository<User> {
  constructor(private pool: Pool) {}

  async findById(id: string): Promise<User | null> {
    const result = await this.pool.query(
      "SELECT * FROM users WHERE id = $1", [id]
    );
    return result.rows[0] ? this.toDomain(result.rows[0]) : null;
  }

  async save(user: User): Promise<void> {
    await this.pool.query(
      `INSERT INTO users (id, name, email) VALUES ($1, $2, $3)
       ON CONFLICT (id) DO UPDATE SET name = $2, email = $3`,
      [user.id, user.name, user.email]
    );
  }

  private toDomain(row: any): User {
    return new User(row.id, row.name, row.email);
  }
}

// In-memory implementation for tests
class InMemoryUserRepository implements Repository<User> {
  private store = new Map<string, User>();

  async findById(id: string): Promise<User | null> {
    return this.store.get(id) ?? null;
  }

  async save(user: User): Promise<void> {
    this.store.set(user.id, user);
  }

  async findAll(): Promise<User[]> {
    return Array.from(this.store.values());
  }

  async delete(id: string): Promise<void> {
    this.store.delete(id);
  }
}
```

## Unit of Work Pattern

Unit of Work maintains a list of objects affected by a business transaction and coordinates writing out changes as a single atomic operation.

**When to use:** Ensuring transactional consistency across multiple repository operations, batching database writes, tracking dirty entities.

```typescript
class UnitOfWork {
  private newEntities: Map<string, any> = new Map();
  private dirtyEntities: Map<string, any> = new Map();
  private removedIds: Set<string> = new Set();

  registerNew(entity: { id: string }): void {
    this.newEntities.set(entity.id, entity);
  }

  registerDirty(entity: { id: string }): void {
    if (!this.newEntities.has(entity.id)) {
      this.dirtyEntities.set(entity.id, entity);
    }
  }

  registerRemoved(id: string): void {
    this.newEntities.delete(id);
    this.dirtyEntities.delete(id);
    this.removedIds.add(id);
  }

  async commit(tx: Transaction): Promise<void> {
    try {
      await tx.begin();
      for (const entity of this.newEntities.values()) await tx.insert(entity);
      for (const entity of this.dirtyEntities.values()) await tx.update(entity);
      for (const id of this.removedIds) await tx.delete(id);
      await tx.commit();
    } catch (err) {
      await tx.rollback();
      throw err;
    } finally {
      this.newEntities.clear();
      this.dirtyEntities.clear();
      this.removedIds.clear();
    }
  }
}
```

## Anti-Patterns to Avoid

**God Object:** A class that knows too much or does too much. Break it into cohesive, single-responsibility components.

**Singleton Abuse:** Using singletons as global mutable state. Prefer dependency injection. Singletons are acceptable for truly global, stateless services like loggers.

**Premature Abstraction:** Creating interfaces and abstract layers before there are multiple concrete implementations. Wait until you have at least two use cases before extracting an abstraction (the Rule of Three).

**Anemic Domain Model:** Domain objects that are pure data holders with all logic in service classes. If the domain is complex, push behavior into domain entities.

**Golden Hammer:** Applying a favorite pattern to every problem. Choose patterns based on the specific problem constraints, not familiarity.

**Speculative Generality:** Building elaborate extension points and plugin systems for future requirements that may never materialize. Build for today's needs with clean code that is easy to refactor later.

**Lava Flow:** Dead code paths, unused abstractions, and experimental features that hardened into permanent infrastructure. Remove dead code aggressively; version control remembers.

**Cargo Cult Programming:** Adopting patterns, architectures, or technologies because "that's what Netflix/Google does" without understanding whether your scale and constraints warrant them. A three-person startup does not need a service mesh.
