---
framework: "Data Modeling"
version: "1.0"
domain: "Data Engineering"
agent: "friday"
tags: ["data-modeling", "ddd", "domain-driven-design", "schema-evolution", "bounded-context", "aggregates"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Data Modeling

## Domain-Driven Design

Domain-driven design (DDD) aligns software design with the business domain. The model is developed collaboratively between domain experts and developers using a shared ubiquitous language.

**Strategic design (big picture):**

- **Ubiquitous language:** A shared vocabulary between business and technical teams. The same terms used in conversations, documentation, and code. If the business calls it a "policy," the code has a `Policy` class, not a `Contract` class.
- **Bounded context:** A boundary within which a particular model applies. The same real-world concept may have different representations in different bounded contexts. A "Customer" in the Sales context has different attributes and behaviors than a "Customer" in the Shipping context.
- **Context mapping:** The relationships between bounded contexts. Types include: Shared Kernel (shared model), Customer-Supplier (upstream-downstream), Conformist (downstream adopts upstream model), Anti-Corruption Layer (downstream translates upstream model), Open Host Service (upstream provides a published API).

**Tactical design (within a bounded context):**

- **Entity:** An object defined by its identity, not its attributes. A `User` with ID `usr_123` is the same user even if their name changes.
- **Value Object:** An object defined by its attributes, not its identity. A `Money(100, "USD")` is equal to another `Money(100, "USD")`. Value objects are immutable.
- **Aggregate:** A cluster of entities and value objects treated as a single unit for data changes. Has a root entity (aggregate root) that is the only entry point for external access.
- **Domain Event:** A record that something meaningful happened in the domain. `OrderPlaced`, `PaymentReceived`, `InventoryDepleted`.
- **Repository:** Provides collection-like access to aggregates. Hides persistence details from the domain.
- **Domain Service:** Encapsulates domain logic that does not naturally belong to a single entity or value object.

## Aggregate Roots

The aggregate root is the entry point for all modifications to an aggregate. External code must go through the root; it cannot reach into the aggregate to modify internal entities directly.

**Aggregate design rules:**

1. **Reference other aggregates by ID, not by object reference.** This prevents aggregates from forming large interconnected graphs and enables independent scaling.
2. **Keep aggregates small.** Large aggregates cause contention (optimistic locking failures) and complexity. Split when an aggregate has too many entities.
3. **Update one aggregate per transaction.** Cross-aggregate consistency is eventual, achieved through domain events. If two aggregates must change together, reconsider the boundary.
4. **Design for invariants.** An aggregate encapsulates the business rules (invariants) that must be consistent within its boundary.

```typescript
class Order {
  private id: OrderId;
  private items: OrderItem[] = [];
  private status: OrderStatus = "draft";
  private readonly maxItems = 50;

  addItem(product: ProductId, quantity: number, price: Money): void {
    if (this.status !== "draft") {
      throw new Error("Cannot add items to a non-draft order");
    }
    if (this.items.length >= this.maxItems) {
      throw new Error("Order cannot have more than 50 items");
    }
    // Invariant enforcement within the aggregate
    this.items.push(new OrderItem(product, quantity, price));
  }

  confirm(): OrderConfirmed {
    if (this.items.length === 0) {
      throw new Error("Cannot confirm an empty order");
    }
    this.status = "confirmed";
    return new OrderConfirmed(this.id, this.total());
  }

  private total(): Money {
    return this.items.reduce(
      (sum, item) => sum.add(item.subtotal()),
      Money.zero("USD")
    );
  }
}
```

**Aggregate ID generation:** Use UUIDs (globally unique, no coordination) or ULIDs (sortable, globally unique). Avoid auto-increment IDs for aggregates (they leak database implementation and cause issues in distributed systems).

## Bounded Contexts

Bounded contexts define the boundaries within which a model is consistent and meaningful. They are the most important pattern in DDD for managing complexity.

**Identifying bounded contexts:**

- Look for different meanings of the same term across teams or departments. "Account" means different things to accounting, customer support, and security.
- Look for different rates of change. The inventory model changes independently from the pricing model.
- Look for different teams or organizational boundaries. Conway's Law suggests that system structure mirrors organizational structure.

**Context map example for an e-commerce system:**

```
+-------------------+       +-------------------+
|   Sales Context   |       |  Catalog Context  |
|                   |       |                   |
|  Customer         | <---> |  Product          |
|  Order            |  ACL  |  Category         |
|  Quote            |       |  Pricing          |
+-------------------+       +-------------------+
        |                           |
        | Events                    | Events
        v                           v
+-------------------+       +-------------------+
| Fulfillment Ctx   |       | Inventory Context |
|                   |       |                   |
|  Shipment         |       |  StockItem        |
|  Delivery         |       |  Warehouse        |
|  Carrier          |       |  Reservation      |
+-------------------+       +-------------------+
```

**Anti-corruption layer (ACL):** When integrating with an external system or a bounded context with a different model, use an ACL to translate between models. The ACL prevents the external model from leaking into your domain.

```typescript
// ACL translating from external payment provider to our domain model
class PaymentProviderACL {
  constructor(private externalClient: StripeClient) {}

  async authorizePayment(amount: Money, method: PaymentMethod): Promise<Authorization> {
    // Translate from our domain to external API
    const stripeResult = await this.externalClient.paymentIntents.create({
      amount: amount.toCents(),
      currency: amount.currency.toLowerCase(),
      payment_method: this.toStripeMethod(method),
    });

    // Translate from external API to our domain
    return new Authorization(
      stripeResult.id,
      stripeResult.status === "succeeded" ? AuthStatus.Approved : AuthStatus.Declined,
      amount,
    );
  }
}
```

## Entity-Relationship Modeling

Entity-relationship (ER) modeling is the foundational technique for relational database design. It models the data as entities (tables), attributes (columns), and relationships (foreign keys).

**Relationship types:**

- **One-to-one (1:1):** User has one Profile. Implemented with a foreign key on either table (or a shared primary key).
- **One-to-many (1:N):** Customer has many Orders. The "many" side has a foreign key to the "one" side.
- **Many-to-many (M:N):** Student enrolls in many Courses; a Course has many Students. Implemented with a join table (`student_courses` with `student_id` and `course_id`).

**ER diagram to schema:**

```sql
-- One-to-many: Customer -> Orders
CREATE TABLE customers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE orders (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID NOT NULL REFERENCES customers(id),
    status TEXT NOT NULL DEFAULT 'pending',
    total_cents BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Many-to-many: Orders -> Products (through order_items)
CREATE TABLE order_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    order_id UUID NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    product_id UUID NOT NULL REFERENCES products(id),
    quantity INT NOT NULL CHECK (quantity > 0),
    unit_price_cents BIGINT NOT NULL,
    UNIQUE (order_id, product_id)
);
```

**Naming conventions:** Use `snake_case` for table and column names. Plural table names (`orders`, not `order`). Foreign keys named `{referenced_table_singular}_id` (e.g., `customer_id`). Timestamps suffixed with `_at` (`created_at`, `updated_at`). Money stored as integers (cents or micros), not floating point.

## Schema Evolution

Schema evolution is the practice of changing database schemas over time while maintaining compatibility with existing data and applications.

**Migration approaches:**

- **Expand and contract (recommended for zero-downtime):** First expand the schema (add new columns/tables), then migrate data, then update application code, then contract (remove old columns/tables).
- **Big-bang migration:** Apply all changes at once during a maintenance window. Simpler but requires downtime.

**Column changes:**

- **Add column:** Safe if nullable or has a default. `ALTER TABLE orders ADD COLUMN tracking_number TEXT;`
- **Rename column:** Dangerous. Use add-copy-drop instead. Add new column, backfill, update code to use new column, drop old column.
- **Change column type:** Dangerous for incompatible type changes. Safe for compatible widening (int -> bigint).
- **Remove column:** Deploy code that stops reading the column first, then drop the column.

## Backward and Forward Compatibility

In distributed systems, producers and consumers of data may be deployed at different times. Schema changes must maintain compatibility.

**Backward compatibility:** New code can read data written by old code. Achieved by: adding optional fields with defaults, never removing required fields, never changing field types.

**Forward compatibility:** Old code can read data written by new code. Achieved by: ignoring unknown fields, using schema registries that validate compatibility.

**Compatibility in serialization formats:**

- **JSON:** Naturally forward-compatible (unknown fields are ignored). Add `"additionalProperties": true` in JSON Schema.
- **Protobuf:** Backward and forward compatible by design. Never reuse field numbers. New fields should have defaults. Use `reserved` for removed fields.
- **Avro:** Full backward/forward/full compatibility modes configurable in Schema Registry. Evolution rules enforced at registration time.

**Compatibility rules:**

| Change | Backward | Forward |
|--------|----------|---------|
| Add optional field | Yes | Yes |
| Add required field | No | No |
| Remove optional field | Yes | Yes (if ignored) |
| Remove required field | No | No |
| Rename field | No | No |
| Change field type | Depends on types | Depends on types |

## Data Contracts

Data contracts are formal agreements between data producers and consumers about the structure, semantics, and quality of shared data. They bring API contract principles to data pipelines and event streams.

**Contract components:**

- **Schema:** The structure of the data (field names, types, constraints).
- **Semantics:** What each field means in business terms. `total_cents` is the order total in US cents, inclusive of tax, exclusive of shipping.
- **Quality guarantees:** Freshness (data is at most 5 minutes old), completeness (no null values in required fields), uniqueness (no duplicate events).
- **SLAs:** Availability (99.9%), latency (events delivered within 1 second of occurrence).
- **Ownership:** Which team is responsible for the data and the contract.

**Contract enforcement:**

```yaml
# data-contract.yaml
apiVersion: datacontract/v1
kind: DataContract
metadata:
  name: order-events
  owner: order-team
  version: "2.1"
spec:
  schema:
    type: object
    properties:
      orderId:
        type: string
        format: uuid
        description: "Unique order identifier"
      customerId:
        type: string
        description: "Customer who placed the order"
      total:
        type: integer
        description: "Order total in cents (USD)"
        minimum: 0
      createdAt:
        type: string
        format: date-time
    required: [orderId, customerId, total, createdAt]
  quality:
    freshness: "5 minutes"
    completeness:
      - field: customerId
        threshold: 100%
    uniqueness:
      - field: orderId
  sla:
    availability: "99.9%"
    latency: "< 1s p99"
```

**Contract testing:** Validate that produced data matches the contract schema. Run as part of the producer's CI pipeline. Alert consumers when a breaking change is proposed. Use schema registry compatibility checks to enforce backward/forward compatibility at publish time.

**Contract versioning:** Use semantic versioning. Major version for breaking changes. Minor for backward-compatible additions. Patch for documentation or quality threshold changes. Support multiple active versions with a deprecation timeline.
