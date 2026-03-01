---
framework: "Event-Driven Architecture"
version: "1.0"
domain: "Data Engineering"
agent: "friday"
tags: ["events", "kafka", "rabbitmq", "nats", "cqrs", "event-sourcing", "messaging"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Event-Driven Architecture

## Event Sourcing

Event sourcing stores the state of an entity as a sequence of state-changing events rather than the current state. The current state is derived by replaying events from the beginning (or from the latest snapshot).

**Event structure:**

```typescript
interface DomainEvent {
  eventId: string;         // Unique event identifier (UUID)
  aggregateId: string;     // The entity this event belongs to
  aggregateType: string;   // e.g., "Order", "Account"
  eventType: string;       // e.g., "OrderCreated", "ItemAdded"
  version: number;         // Sequence number for optimistic concurrency
  timestamp: string;       // ISO 8601 timestamp
  payload: Record<string, unknown>;  // Event-specific data
  metadata: {
    correlationId: string; // Ties related events across services
    causationId: string;   // The event/command that caused this event
    userId?: string;       // Who triggered this event
  };
}
```

**Aggregate reconstruction:**

```typescript
class OrderAggregate {
  private state: OrderState = { items: [], status: "draft", total: 0 };

  static fromEvents(events: DomainEvent[]): OrderAggregate {
    const aggregate = new OrderAggregate();
    for (const event of events) {
      aggregate.apply(event);
    }
    return aggregate;
  }

  private apply(event: DomainEvent): void {
    switch (event.eventType) {
      case "OrderCreated":
        this.state = { ...this.state, status: "pending", ...event.payload };
        break;
      case "ItemAdded":
        this.state.items.push(event.payload as LineItem);
        this.state.total += (event.payload as LineItem).price;
        break;
      case "OrderConfirmed":
        this.state.status = "confirmed";
        break;
    }
  }
}
```

**Snapshotting:** For aggregates with many events, replaying from the beginning is expensive. Periodically save a snapshot of the aggregate state. On load, read the latest snapshot and replay only events after the snapshot version.

**Event store requirements:** Append-only writes, read by aggregate ID (in order), optimistic concurrency control (reject writes if the expected version does not match), support for event subscription/polling.

## CQRS with Events

CQRS separates the write model (commands) from the read model (queries). Events bridge the two: the write side produces events, and the read side consumes them to build projections.

**Write side flow:**

```
Command -> Command Handler -> Aggregate -> Events -> Event Store
```

**Read side flow:**

```
Events -> Event Handler/Projector -> Read Model (database/search index/cache)
```

**Projection example:**

```typescript
class OrderListProjection {
  constructor(private db: Database) {}

  async handle(event: DomainEvent): Promise<void> {
    switch (event.eventType) {
      case "OrderCreated":
        await this.db.insert("order_list", {
          id: event.aggregateId,
          customer_name: event.payload.customerName,
          status: "pending",
          total: 0,
          created_at: event.timestamp,
        });
        break;

      case "ItemAdded":
        await this.db.query(
          `UPDATE order_list SET total = total + $1 WHERE id = $2`,
          [event.payload.price, event.aggregateId]
        );
        break;

      case "OrderConfirmed":
        await this.db.query(
          `UPDATE order_list SET status = 'confirmed' WHERE id = $1`,
          [event.aggregateId]
        );
        break;
    }
  }
}
```

**Multiple projections:** The same events can feed multiple read models: a relational database for CRUD queries, Elasticsearch for full-text search, Redis for real-time dashboards, a data warehouse for analytics.

**Rebuild projections:** Since events are the source of truth, any read model can be rebuilt from scratch by replaying all events through the projector. This enables adding new read models or fixing bugs in existing projections.

## Message Brokers

### Apache Kafka

Kafka is a distributed event streaming platform. It stores events in ordered, partitioned, replicated logs (topics).

**Key concepts:**

- **Topic:** A named category of events. Events within a topic are ordered per partition.
- **Partition:** A topic is split into partitions for parallelism. Events with the same key go to the same partition (ordering guarantee per key).
- **Consumer group:** Multiple consumers share the work of consuming a topic. Each partition is assigned to exactly one consumer in the group.
- **Offset:** Each message has a unique offset within its partition. Consumers track their position by committing offsets.
- **Retention:** Messages are retained for a configurable time or size, regardless of consumption. Consumers can re-read old messages.

**Producer configuration:**

```properties
acks=all                    # Wait for all replicas to acknowledge
retries=3                   # Retry on transient failures
enable.idempotence=true     # Prevent duplicate messages on retries
max.in.flight.requests.per.connection=5  # With idempotence, safe up to 5
linger.ms=5                 # Batch messages for 5ms before sending
batch.size=16384            # Maximum batch size in bytes
compression.type=lz4        # Compress batches
```

**Consumer configuration:**

```properties
group.id=order-processor
auto.offset.reset=earliest        # Start from beginning if no committed offset
enable.auto.commit=false          # Manual offset commit for at-least-once
max.poll.records=500              # Maximum records per poll
session.timeout.ms=30000          # Consumer failure detection timeout
```

**Kafka use cases:** Event streaming, log aggregation, change data capture, metrics pipelines, real-time analytics, inter-service communication.

### RabbitMQ

RabbitMQ is a message broker implementing AMQP. It focuses on message routing, delivery guarantees, and flexible topology.

**Key concepts:**

- **Exchange:** Receives messages from producers and routes them to queues based on routing rules. Types: direct, topic, fanout, headers.
- **Queue:** Stores messages until consumed. Multiple consumers can share a queue (competing consumers pattern).
- **Binding:** Rules that connect exchanges to queues.

**Exchange types:**

- **Direct:** Routes to queues with an exact matching routing key. `payment.completed` routes to queues bound with `payment.completed`.
- **Topic:** Pattern-based routing. `order.*.created` matches `order.us.created` and `order.eu.created`. `order.#` matches `order.us.created` and `order.us.shipped.express`.
- **Fanout:** Routes to all bound queues regardless of routing key. Broadcast pattern.

**RabbitMQ use cases:** Task queues, RPC, pub/sub, work distribution, delayed messages (with plugin).

### NATS

NATS is a lightweight, high-performance messaging system. NATS JetStream adds persistence, exactly-once semantics, and stream processing.

**Core NATS:** At-most-once pub/sub. No persistence. Fastest option when message loss is acceptable (metrics, real-time updates).

**JetStream:** Adds persistence, at-least-once/exactly-once delivery, consumer groups, replay, and key-value store.

**NATS use cases:** Microservice request/reply, IoT messaging, edge computing, real-time notifications.

## Event Schemas

Events are a contract between producers and consumers. Schema management prevents breaking changes.

**Schema registry:** A central repository for event schemas. Producers register schemas; consumers validate against them. Tools: Confluent Schema Registry (Avro, Protobuf, JSON Schema), AWS Glue Schema Registry.

**Schema formats:**

- **Avro:** Binary format, compact, schema evolution support, requires schema registry. Preferred for Kafka.
- **Protobuf:** Binary format, strongly typed, code generation, good backward/forward compatibility.
- **JSON Schema:** Human-readable, widely supported, larger payload size.
- **CloudEvents:** A specification for describing event data in a common way. Defines required attributes (source, type, id, time) and extension attributes.

**Event naming conventions:** Use past tense for events (they describe something that happened): `OrderCreated`, `PaymentProcessed`, `InventoryReserved`. Use present tense for commands: `CreateOrder`, `ProcessPayment`.

## Dead Letter Queues

A dead letter queue (DLQ) receives messages that cannot be processed after a configured number of retries. It prevents poison messages from blocking the queue.

**DLQ workflow:**

1. Consumer receives a message.
2. Processing fails (deserialization error, validation failure, transient downstream failure).
3. Message is retried N times with exponential backoff.
4. After N failures, message is moved to the DLQ.
5. Operations team is alerted on DLQ depth.
6. DLQ messages are inspected, fixed, and replayed, or discarded.

**Implementation in Kafka:**

```typescript
async function consumeWithDLQ(message: KafkaMessage): Promise<void> {
  try {
    await processMessage(message);
  } catch (error) {
    const retryCount = getRetryCount(message);
    if (retryCount < MAX_RETRIES) {
      await publishToRetryTopic(message, retryCount + 1);
    } else {
      await publishToDLQ(message, error);
      logger.error("Message moved to DLQ", {
        topic: message.topic,
        partition: message.partition,
        offset: message.offset,
        error: error.message,
      });
    }
  }
}
```

**DLQ monitoring:** Track DLQ depth as a key metric. Alert when depth exceeds zero (for critical topics) or a threshold. Provide tooling to inspect DLQ messages, replay them to the original topic, or discard them.

## Exactly-Once Semantics

True exactly-once delivery is extremely difficult in distributed systems. In practice, exactly-once processing is achieved through idempotent consumers combined with at-least-once delivery.

**Idempotent consumers:** Processing the same message multiple times produces the same result as processing it once. Strategies:

- **Idempotency key:** Include a unique ID in each message. Before processing, check if the ID has been processed. Use a database table or cache to track processed IDs.
- **Conditional writes:** Use database constraints (unique indexes, optimistic locking) to prevent duplicate effects.
- **Transactional outbox:** Write the event and the side effect in the same database transaction. If the transaction succeeds, both are recorded. If it fails, neither is.

**Kafka exactly-once:**

- **Idempotent producer:** `enable.idempotence=true`. Kafka deduplicates messages from the same producer session.
- **Transactions:** Kafka supports read-process-write transactions. Consume from an input topic, produce to an output topic, and commit the consumer offset atomically. Uses `isolation.level=read_committed` on consumers.

## Event Choreography vs Orchestration

**Choreography:** Each service reacts to events from other services and publishes its own events. No central coordinator. Services are loosely coupled. Simple for small flows but hard to reason about, debug, and monitor for complex flows with many steps.

```
OrderService publishes OrderCreated
  -> PaymentService reacts, publishes PaymentCompleted
    -> InventoryService reacts, publishes StockReserved
      -> ShippingService reacts, publishes ShipmentScheduled
```

**Orchestration:** A central orchestrator (saga coordinator) directs the flow by sending commands to services and handling their responses. Easier to understand and monitor. The orchestrator is a potential single point of failure and coupling point.

```
Orchestrator sends AuthorizePayment to PaymentService
  PaymentService responds PaymentAuthorized
Orchestrator sends ReserveStock to InventoryService
  InventoryService responds StockReserved
Orchestrator sends ScheduleShipment to ShippingService
```

**When to use choreography:** Simple flows with 2-3 steps. Services that are truly independent. When avoiding a central coordinator is a priority.

**When to use orchestration:** Complex flows with many steps and branching logic. When you need clear visibility into the process state. When compensation (rollback) logic is complex.

**Hybrid approach:** Use choreography for loosely coupled, independent reactions (send email on OrderCreated, update analytics). Use orchestration for the critical path where the flow must be reliable and observable (order fulfillment saga).
