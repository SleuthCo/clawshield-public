---
framework: "Microservices"
version: "1.0"
domain: "Software Architecture"
agent: "friday"
tags: ["microservices", "distributed-systems", "saga", "cqrs", "event-sourcing", "service-mesh"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Microservices Architecture

## Service Decomposition

Decompose by business capability, not by technical layer. Each microservice should own a bounded context from domain-driven design and be independently deployable.

**Decomposition strategies:**

- **By business capability:** Payment Service, Order Service, Inventory Service. Each aligns with a business function and has a dedicated team.
- **By subdomain:** Core domain (competitive advantage, invest heavily), supporting subdomain (necessary but not differentiating), generic subdomain (commodity, buy or use open-source).
- **Strangler fig:** Incrementally extract functionality from a monolith. Route traffic to the new service for migrated features while the monolith still handles the rest.

**Service sizing heuristics:**

- A service should be owned by a single team (two-pizza team rule).
- It should be rewritable in two to four weeks.
- It encapsulates a single aggregate root or bounded context.
- If two services always deploy together, they should probably be one service.
- If a change requires coordinated deployments across services, the boundary is likely wrong.

**Data ownership:** Each service owns its data store. No shared databases. Cross-service data access happens through APIs or events. This is the hardest discipline to maintain and the most important.

## API Gateway Patterns

An API gateway sits between clients and microservices, handling cross-cutting concerns and request routing.

**Responsibilities:** Request routing, protocol translation, authentication/authorization, rate limiting, response aggregation, SSL termination, request/response transformation.

**Patterns:**

- **Simple gateway:** Routes requests to backend services, handles auth. Tools: Kong, NGINX, AWS API Gateway, Envoy.
- **Backend for Frontend (BFF):** Separate gateway per client type (web BFF, mobile BFF, third-party BFF). Each gateway tailors the API to its client's needs, reducing over-fetching.
- **Gateway aggregation:** A single client request fans out to multiple services, and the gateway aggregates the responses. Reduces client-side complexity and round trips.

**Anti-patterns:**

- Gateway becoming a monolith with business logic. Keep it thin; it should only handle cross-cutting concerns.
- Single shared gateway for all clients leading to coupling. Use BFF pattern when client needs diverge significantly.

## Service Mesh

A service mesh provides a dedicated infrastructure layer for service-to-service communication. It handles traffic management, security, and observability without application code changes.

**Components:**

- **Data plane:** Sidecar proxies (Envoy) deployed alongside each service instance. Intercept all inbound and outbound traffic.
- **Control plane:** Manages and configures the sidecar proxies. Istio, Linkerd, or Consul Connect.

**Capabilities:**

- **Traffic management:** Canary deployments, A/B testing, traffic splitting, retries, timeouts, circuit breaking.
- **Security:** Mutual TLS (mTLS) between services, certificate rotation, authorization policies.
- **Observability:** Automatic metrics collection, distributed tracing injection, access logging.

**When to adopt:** Service mesh adds operational complexity. Worthwhile when you have more than 10-15 services and need consistent security, observability, and traffic management. For fewer services, a library-based approach (e.g., gRPC interceptors) may suffice.

## Saga Pattern

Sagas manage distributed transactions across multiple services without two-phase commit. Each step has a compensating action that undoes the step if a later step fails.

**Choreography-based saga:** Each service listens for events and publishes its own events. No central coordinator. Simple for small sagas (2-3 steps) but hard to reason about for complex flows.

```
Order Service -> OrderCreated event
  -> Payment Service processes payment -> PaymentCompleted event
    -> Inventory Service reserves stock -> StockReserved event
      -> Shipping Service schedules delivery

If PaymentFailed:
  -> Order Service cancels order (compensating action)
```

**Orchestration-based saga:** A central saga orchestrator coordinates the steps. It sends commands to services and handles responses. Easier to understand and debug for complex flows.

```typescript
class CreateOrderSaga {
  async execute(order: Order): Promise<void> {
    try {
      await this.paymentService.authorize(order.payment);
      await this.inventoryService.reserve(order.items);
      await this.shippingService.schedule(order.shippingAddress);
      await this.orderService.confirm(order.id);
    } catch (error) {
      await this.compensate(order, error);
    }
  }

  private async compensate(order: Order, error: Error): Promise<void> {
    // Reverse completed steps in reverse order
    await this.shippingService.cancelSchedule(order.id).catch(log);
    await this.inventoryService.releaseReservation(order.id).catch(log);
    await this.paymentService.reverseAuthorization(order.id).catch(log);
    await this.orderService.reject(order.id, error.message);
  }
}
```

**Key considerations:** Compensating actions must be idempotent. Use correlation IDs to track saga instances. Implement timeouts for each step. Store saga state for recovery after crashes.

## CQRS (Command Query Responsibility Segregation)

CQRS separates the read model from the write model. Commands modify state through a write store; queries read from a read-optimized store.

**When to use CQRS:**

- Read and write workloads have vastly different scaling requirements.
- Read models need different shapes than the write model (denormalized views, search indexes).
- Domain complexity benefits from separating the command processing logic.

**Implementation:**

- **Write side:** Validates commands, applies business rules, persists to the write store (normalized relational database or event store).
- **Read side:** Subscribes to domain events, builds denormalized projections optimized for specific queries (Elasticsearch, Redis, materialized views).
- **Synchronization:** Events flow from write side to read side. Accept eventual consistency between write and read models.

**Simple CQRS:** Same database, different models (write through ORM entities, read through raw SQL or views). No event bus needed. Good starting point.

**Full CQRS with event sourcing:** Write side stores events. Read side projects events into query-optimized views. Maximum flexibility, maximum complexity.

## Event Sourcing

Instead of storing current state, store the sequence of events that led to the current state. The current state is derived by replaying events.

**Benefits:** Complete audit trail, temporal queries (state at any point in time), event replay for bug investigation, natural fit with CQRS and event-driven architecture.

**Challenges:** Event schema evolution (upcasting), snapshot optimization for aggregates with many events, eventual consistency, increased storage, complexity of debugging through event replay.

**Event store design:**

```
events table:
  - aggregate_id (partition key)
  - version (sort key, for optimistic concurrency)
  - event_type
  - payload (JSON)
  - metadata (correlation_id, causation_id, timestamp, user_id)
```

**Snapshotting:** For aggregates with thousands of events, periodically save a snapshot of the aggregate state. On load, read the latest snapshot and replay only events after the snapshot.

## Circuit Breaker Pattern

Circuit breaker prevents cascading failures by stopping calls to a failing service. It has three states: Closed (normal), Open (failing fast), Half-Open (testing recovery).

**State transitions:**

1. **Closed:** Requests pass through normally. Failures are counted. When failure count exceeds a threshold within a time window, the circuit opens.
2. **Open:** All requests fail immediately without reaching the downstream service. After a configured timeout, the circuit moves to half-open.
3. **Half-Open:** A limited number of test requests are allowed through. If they succeed, the circuit closes. If they fail, the circuit opens again.

**Configuration parameters:** Failure threshold (e.g., 5 failures), time window (e.g., 60 seconds), open timeout (e.g., 30 seconds), half-open max requests (e.g., 3).

**Fallback strategies:** Return cached data, return a default response, degrade gracefully (show partial results), queue the request for later processing.

## Bulkhead Pattern

Bulkhead isolates critical resources so that a failure in one area does not exhaust resources for another. Named after ship bulkheads that prevent flooding from spreading.

**Implementation approaches:**

- **Thread pool isolation:** Each downstream service gets its own thread pool. If the payment service is slow, only its thread pool is exhausted; other services are unaffected.
- **Connection pool isolation:** Separate database connection pools per service or per query type (read pool, write pool, analytics pool).
- **Semaphore isolation:** Limit concurrent requests to each downstream service using semaphores.
- **Process isolation:** Run critical components in separate processes or containers.

## Sidecar Pattern

A sidecar is a co-deployed process that extends the primary service with supporting functionality. It runs in the same pod or host and communicates over localhost.

**Common sidecar uses:** Service mesh proxy (Envoy), log collection (Fluentd), configuration management, TLS termination, health checking, secrets injection.

**Benefits:** Language-agnostic (sidecars work with any primary service language), separation of concerns, independent lifecycle from the primary service.

## Strangler Fig Migration

Incrementally migrate a monolith to microservices by gradually replacing specific functionality with new services while keeping the monolith running.

**Steps:**

1. **Identify:** Choose a bounded context to extract. Start with the least coupled, most independently valuable component.
2. **Intercept:** Place a routing layer (API gateway or reverse proxy) in front of the monolith.
3. **Extract:** Build the new service. Route traffic for the extracted capability to the new service.
4. **Migrate data:** Move data ownership to the new service. Use change data capture or dual-write patterns during transition.
5. **Remove:** Delete the old code from the monolith once the new service is stable.

**Key principle:** The monolith should never depend on the new microservice. Dependencies flow one way: microservice calls the monolith (via anti-corruption layer) during transition, not the other way around.
