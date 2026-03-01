---
framework: "Database Patterns"
version: "1.0"
domain: "Data Engineering"
agent: "friday"
tags: ["database", "sql", "nosql", "indexing", "normalization", "migration", "partitioning"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Database Patterns

## Relational Database Design

### Normalization

Normalization eliminates data redundancy and anomalies (insert, update, delete) by organizing data into related tables.

**First Normal Form (1NF):** Every column contains atomic (indivisible) values. No repeating groups. Each row is unique (has a primary key).

**Second Normal Form (2NF):** Must be in 1NF. Every non-key column depends on the entire primary key (not just part of a composite key). Addresses partial dependencies.

**Third Normal Form (3NF):** Must be in 2NF. No transitive dependencies: non-key columns depend only on the primary key, not on other non-key columns.

**When to denormalize:** Normalization optimizes for write consistency; denormalization optimizes for read performance. Denormalize when: read performance is critical and writes are infrequent, join complexity is causing unacceptable query latency, reporting and analytics queries need pre-aggregated data.

**Practical guideline:** Start normalized (3NF). Denormalize specific tables or add materialized views only when performance data justifies it.

### Indexing Strategy

Indexes speed up reads at the cost of slower writes and additional storage.

**B-tree indexes (default):** Good for equality, range queries, and sorting. Use for primary keys, foreign keys, and frequently filtered columns.

**Hash indexes:** Fastest for equality comparisons. Not useful for range queries or sorting. Available in PostgreSQL but rarely needed; B-tree handles most cases.

**GIN (Generalized Inverted Index):** For full-text search, JSONB queries, array containment. PostgreSQL-specific.

**GiST (Generalized Search Tree):** For geometric data, full-text search, range types. PostgreSQL-specific.

**Composite indexes:** Index on multiple columns. Column order matters: `(customer_id, created_at)` supports queries filtering on `customer_id` alone or `customer_id AND created_at`, but NOT `created_at` alone (leftmost prefix rule).

```sql
-- Supports: WHERE customer_id = ? AND status = ? ORDER BY created_at
CREATE INDEX idx_orders_customer_status_date
ON orders (customer_id, status, created_at DESC);

-- Covering index (includes all needed columns, avoids table lookup)
CREATE INDEX idx_orders_covering
ON orders (customer_id, status)
INCLUDE (total, created_at);

-- Partial index (only indexes relevant rows, smaller and faster)
CREATE INDEX idx_orders_pending
ON orders (customer_id, created_at)
WHERE status = 'pending';

-- Expression index
CREATE INDEX idx_users_email_lower
ON users (LOWER(email));
```

**Index maintenance:** Monitor unused indexes with `pg_stat_user_indexes` (PostgreSQL). Remove unused indexes. Rebuild bloated indexes periodically. Monitor index size relative to table size.

## NoSQL Patterns

### Document Store (MongoDB, Couchbase)

Store data as semi-structured documents (JSON/BSON). Ideal for varied or evolving schemas, nested data, and read-heavy workloads where the access pattern is known.

**Data modeling:**

- **Embed** related data within a document when data is accessed together, relationships are one-to-few, and embedded data does not need independent access.
- **Reference** related data with IDs when data is accessed independently, relationships are one-to-many or many-to-many, and the embedded document would be very large.

```javascript
// Embedded (denormalized): good for read performance
{
  _id: "order_123",
  customer: {
    id: "cust_456",
    name: "Alice",
    email: "alice@example.com"
  },
  items: [
    { productId: "prod_1", name: "Widget", quantity: 2, price: 9.99 },
    { productId: "prod_2", name: "Gadget", quantity: 1, price: 24.99 }
  ],
  total: 44.97
}

// Referenced (normalized): good when customer data is shared
{
  _id: "order_123",
  customerId: "cust_456",  // reference
  items: ["item_1", "item_2"],  // references
  total: 44.97
}
```

### Key-Value Store (Redis, DynamoDB, Memcached)

Simple key-to-value mapping. Fastest possible reads and writes. Use for caching, session storage, rate limiting, leaderboards, and real-time counters.

**Redis data structures:**

- **String:** Simple values, counters, cached JSON.
- **Hash:** Object-like structures. `HSET user:123 name "Alice" email "alice@example.com"`.
- **List:** Ordered collections. Activity feeds, queues.
- **Set:** Unique collections. Tags, followers, online users.
- **Sorted Set:** Ranked collections. Leaderboards, priority queues, time-series data.
- **Stream:** Append-only log. Event sourcing, message queues.

### Graph Database (Neo4j, Amazon Neptune)

Store data as nodes and edges. Ideal for highly connected data: social networks, recommendation engines, fraud detection, knowledge graphs.

```cypher
// Find friends of friends who are not already friends
MATCH (me:User {id: "usr_123"})-[:FRIEND]->(friend)-[:FRIEND]->(fof)
WHERE NOT (me)-[:FRIEND]->(fof) AND fof <> me
RETURN fof.name, COUNT(friend) AS mutual_friends
ORDER BY mutual_friends DESC
LIMIT 10
```

### Column-Family Store (Cassandra, HBase, ScyllaDB)

Organize data by columns rather than rows. Optimized for write-heavy workloads, time-series data, and wide rows. Data is partitioned by a partition key and sorted by clustering columns within each partition.

```cql
CREATE TABLE events (
    tenant_id UUID,
    event_date DATE,
    event_time TIMESTAMP,
    event_type TEXT,
    payload TEXT,
    PRIMARY KEY ((tenant_id, event_date), event_time)
) WITH CLUSTERING ORDER BY (event_time DESC);

-- Queries must include the partition key (tenant_id, event_date)
SELECT * FROM events
WHERE tenant_id = ? AND event_date = '2024-03-15'
AND event_time > '2024-03-15T10:00:00Z';
```

## Connection Pooling

Opening a database connection involves TCP handshake, TLS negotiation, authentication, and session setup. Connection pooling amortizes this cost by reusing connections.

**Pool sizing (PostgreSQL):** A common formula is `pool_size = (core_count * 2) + effective_spindle_count`. For SSD, start with `core_count * 2 + 1`. Increase based on load testing. Too many connections overwhelm the database with context switching.

**Connection pool per service instance:** Each service instance maintains its own pool. Total connections = pool_size * instance_count. Ensure this does not exceed the database's `max_connections`.

**PgBouncer (PostgreSQL):** A lightweight connection pooler that sits between the application and PostgreSQL. Multiplexes many client connections onto fewer database connections. Modes: session pooling (one-to-one), transaction pooling (shared between transactions, most common), statement pooling (shared between statements, most aggressive).

**HikariCP (Java):** High-performance JDBC connection pool. Configure `maximumPoolSize`, `minimumIdle`, `connectionTimeout`, `idleTimeout`, `maxLifetime`.

## Migration Strategies

Database migrations change the schema and data over time. Migrations must be version-controlled, reproducible, and reversible.

**Migration tools:** Flyway (Java, SQL-based), Alembic (Python/SQLAlchemy), golang-migrate (Go), Prisma Migrate (TypeScript), Liquibase (cross-platform).

**Migration file naming:** Use sequential numbering or timestamps: `001_create_users.sql`, `002_add_email_index.sql`. Timestamps (`20240315120000_create_users.sql`) avoid conflicts in parallel development.

**Reversible migrations:** Every migration should have an up (apply) and down (revert) script. Test the down migration before deploying the up migration.

**Zero-downtime migrations:**

1. **Add column (nullable or with default):** Safe. No locks on reads.
2. **Backfill data:** Batch updates with `WHERE id BETWEEN x AND y` and `LIMIT`. Do not update all rows in one transaction.
3. **Deploy code that writes to both old and new columns.**
4. **Make new column NOT NULL (if needed).** Add constraint as NOT VALID first, then validate separately.
5. **Deploy code that reads from new column.**
6. **Drop old column.**

**Dangerous operations:**

- Adding a NOT NULL column without a default locks the table in PostgreSQL.
- Renaming a column breaks existing queries. Use the add-copy-drop pattern instead.
- Dropping a column that is still referenced by running application code causes errors.
- Large table alterations: use `pg_repack` or `gh-ost` for online schema changes in MySQL.

## Read Replicas

Read replicas are copies of the primary database that serve read-only queries. They distribute read load and improve query latency.

**Implementation:**

- Direct reads to replicas, writes to the primary.
- Handle replication lag: after a write, read from the primary for a short window (read-your-writes consistency).
- Use connection-level routing or a proxy (ProxySQL, PgBouncer, AWS RDS Proxy).

**Replication lag monitoring:** Track `pg_stat_replication` (PostgreSQL) or `Seconds_Behind_Master` (MySQL). Alert when lag exceeds acceptable thresholds. High lag means reads from replicas return stale data.

## Partitioning

Partitioning splits a large table into smaller, more manageable pieces based on a column value.

**Range partitioning:** Split by date range (monthly, yearly). Common for time-series data, logs, and events.

```sql
CREATE TABLE events (
    id BIGINT,
    created_at TIMESTAMP,
    data JSONB
) PARTITION BY RANGE (created_at);

CREATE TABLE events_2024_01 PARTITION OF events
    FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');

CREATE TABLE events_2024_02 PARTITION OF events
    FOR VALUES FROM ('2024-02-01') TO ('2024-03-01');
```

**List partitioning:** Split by discrete values (region, status, tenant).

**Hash partitioning:** Distribute rows evenly across N partitions using a hash of the partition key. Good when there is no natural range or list partition key.

**Benefits:** Query performance improves when queries filter on the partition key (partition pruning). Old partitions can be dropped efficiently (instead of DELETE, just DROP PARTITION). Maintenance operations (VACUUM, REINDEX) can run on individual partitions.

**Limitations:** Queries that do not filter on the partition key scan all partitions. Unique constraints must include the partition key. Cross-partition queries can be slower than a single large table.
