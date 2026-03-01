---
framework: "System Design"
version: "1.0"
domain: "Software Architecture"
agent: "friday"
tags: ["distributed-systems", "cap-theorem", "consensus", "sharding", "caching", "load-balancing"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Distributed Systems Fundamentals

## CAP Theorem

The CAP theorem states that a distributed data store can provide at most two of three guarantees simultaneously: Consistency, Availability, and Partition tolerance.

**Consistency (C):** Every read receives the most recent write or an error. All nodes see the same data at the same time.

**Availability (A):** Every request receives a non-error response, without guarantee that it contains the most recent write. The system continues to operate.

**Partition Tolerance (P):** The system continues to operate despite network partitions between nodes.

**Practical implications:** Since network partitions are inevitable in distributed systems, the real choice is between CP and AP during a partition:

- **CP systems:** Choose consistency over availability during a partition. When nodes cannot communicate, the system refuses requests rather than return stale data. Examples: ZooKeeper, etcd, HBase, MongoDB (with majority write concern), most relational databases.
- **AP systems:** Choose availability over consistency during a partition. Return stale data rather than refuse requests. Eventually converge when the partition heals. Examples: Cassandra, DynamoDB, CouchDB, DNS.

**PACELC extension:** When there is no partition (P), the system must still choose between latency (L) and consistency (C). Many systems are PA/EL (available during partition, low-latency otherwise) or PC/EC (consistent during partition, consistent otherwise).

## Consistency Models

Consistency models define the contract between the data store and application regarding when writes become visible to reads.

**Strong consistency (linearizability):** Every operation appears to take effect atomically at a single point in time. Reads always return the latest write. Simplest to reason about but highest latency.

**Sequential consistency:** All operations appear in some total order that is consistent with the program order of each individual process. Weaker than linearizability because the total order does not need to respect real-time ordering.

**Causal consistency:** Operations that are causally related are seen in the same order by all processes. Concurrent (causally unrelated) operations may be seen in different orders by different processes.

**Eventual consistency:** If no new updates are made, all replicas will eventually converge to the same value. No guarantee about when. Common in AP systems, caches, and DNS.

**Read-your-writes consistency:** A process always sees its own writes. Common requirement even in eventually consistent systems. Implementations: sticky sessions, reading from the write replica, tracking write timestamps.

**Tunable consistency (Cassandra model):** Configure consistency level per operation. `QUORUM` reads and writes give strong consistency. `ONE` gives lowest latency with eventual consistency. Formula: R + W > N ensures strong consistency (R = read replicas, W = write replicas, N = total replicas).

## Consensus Algorithms

Consensus algorithms allow distributed nodes to agree on a single value even when some nodes fail. They are the foundation of distributed coordination.

**Raft:** Designed for understandability. A leader-based protocol with three roles: Leader, Follower, Candidate. Leader handles all client requests and replicates log entries to followers. If the leader fails, a new election occurs. Used in etcd, Consul, CockroachDB.

**Raft phases:**
1. **Leader election:** Followers timeout waiting for heartbeats, become candidates, request votes. Candidate with majority becomes leader. Terms (monotonic epoch numbers) prevent stale leaders.
2. **Log replication:** Leader appends entries to its log, sends to followers. Entry is committed when a majority of nodes have replicated it. Leader notifies followers of committed entries.
3. **Safety:** A candidate cannot win an election unless its log is at least as up-to-date as any other node in the majority.

**Paxos:** The original consensus algorithm. Guarantees safety (agreement and validity) in any asynchronous network with fewer than N/2 failures. More complex than Raft. Multi-Paxos optimizes for repeated consensus decisions. Used in Google Chubby, Azure Storage.

**Practical use:** Most developers use consensus through tools (etcd, ZooKeeper, Consul) rather than implementing it directly. Use consensus for leader election, configuration management, distributed locks, and service discovery.

## Sharding (Data Partitioning)

Sharding distributes data across multiple nodes to scale writes, storage, and read throughput horizontally.

**Sharding strategies:**

- **Hash-based sharding:** `shard = hash(key) % num_shards`. Distributes data evenly. Adding or removing shards requires rehashing (use consistent hashing to minimize redistribution).
- **Range-based sharding:** Data is split by key ranges (e.g., A-M on shard 1, N-Z on shard 2). Supports range queries efficiently. Risk of hot spots if data is not uniformly distributed.
- **Geographic sharding:** Data is partitioned by region. Users in Europe hit European shards. Reduces latency and helps with data sovereignty compliance.
- **Directory-based sharding:** A lookup service maps keys to shards. Most flexible but the directory is a potential bottleneck and single point of failure.

**Consistent hashing:** Maps both keys and nodes onto a hash ring. Each key is assigned to the nearest node clockwise on the ring. When a node is added or removed, only keys in the affected segment are redistributed. Virtual nodes ensure even distribution.

**Cross-shard operations:** Avoid cross-shard joins and transactions. Design data models so that commonly accessed data is co-located on the same shard (shard by tenant ID, user ID, or organization ID).

## Replication

Replication copies data to multiple nodes for fault tolerance, read scalability, and geographic distribution.

**Single-leader replication:** One node accepts writes (leader), replicates to followers. Followers serve reads. Simple. Risk: leader is a single point of failure (mitigated by automatic failover). Examples: PostgreSQL streaming replication, MySQL replication.

**Multi-leader replication:** Multiple nodes accept writes. Enables multi-datacenter writes. Complex due to write conflicts. Conflict resolution strategies: last-writer-wins (data loss risk), merge/CRDT, application-level resolution. Examples: CouchDB, active-active PostgreSQL with BDR.

**Leaderless replication:** Any node accepts reads and writes. Clients send writes to multiple nodes. Read repair and anti-entropy processes fix inconsistencies. Uses quorum reads/writes for consistency. Examples: Cassandra, DynamoDB, Riak.

**Replication lag:** In asynchronous replication, followers may be behind the leader. This causes read-after-write inconsistencies. Mitigations: reading from the leader for recently written data, monotonic reads (always reading from the same replica), causal consistency tracking.

## Load Balancing

Load balancers distribute traffic across multiple server instances to improve throughput, reduce latency, and provide fault tolerance.

**Algorithms:**

- **Round-robin:** Distribute requests sequentially across servers. Simple but ignores server load and request cost.
- **Weighted round-robin:** Assign weights based on server capacity. Servers with higher weight get more requests.
- **Least connections:** Route to the server with fewest active connections. Better for long-lived connections or variable request processing times.
- **Least response time:** Route to the server with lowest response time and fewest connections.
- **Consistent hashing:** Route based on request properties (e.g., user ID). Same user always hits the same server. Useful for session affinity and cache locality.
- **Random:** Simple and surprisingly effective when servers are homogeneous and request costs are uniform.

**Layer 4 vs Layer 7:**

- **Layer 4 (transport):** Routes based on IP and port. Cannot inspect request content. Very fast. Examples: AWS NLB, HAProxy in TCP mode.
- **Layer 7 (application):** Routes based on HTTP headers, URL path, cookies, etc. Can perform content-based routing, SSL termination, response compression. Examples: AWS ALB, NGINX, Envoy.

**Health checks:** Active health checks (load balancer pings servers) and passive health checks (load balancer monitors response codes). Remove unhealthy servers from the pool automatically.

## Caching Strategies

Caching stores frequently accessed data in fast storage to reduce latency and database load.

**Cache-aside (lazy loading):** Application checks cache first; on miss, reads from the database, writes to cache. Most common pattern. Risk: stale data if the database is updated without invalidating the cache.

```
read(key):
  value = cache.get(key)
  if value is None:
    value = db.query(key)
    cache.set(key, value, ttl=300)
  return value
```

**Write-through:** Application writes to cache and database simultaneously. Cache is always consistent. Higher write latency. Risk: caching data that is never read.

**Write-behind (write-back):** Application writes to cache; cache asynchronously writes to database. Lowest write latency. Risk: data loss if cache fails before flush.

**Read-through:** Cache itself fetches from the database on a miss (cache is the data source). Simplifies application code. Used in CDNs and cache providers like Memcached with plugins.

**Cache invalidation strategies:** Time-based (TTL), event-based (invalidate on write), version-based (cache key includes version number). Cache invalidation is one of the two hard problems in computer science -- prefer TTL-based expiration with short TTLs over complex invalidation logic.

**Multi-level caching:** L1 (in-process, fastest, smallest), L2 (distributed cache like Redis, fast, shared), L3 (CDN, for static assets and API responses). Check each level in order.

## Message Queues

Message queues decouple producers from consumers, enabling asynchronous processing, load leveling, and fault tolerance.

**Queue semantics:**

- **At-most-once:** Message may be lost but never duplicated. Fire-and-forget. Acceptable for metrics, logs.
- **At-least-once:** Message will be delivered at least once but may be duplicated. Consumer must be idempotent. Most common guarantee.
- **Exactly-once:** Message is delivered exactly once. Very expensive to guarantee; typically achieved through idempotent consumers combined with at-least-once delivery.

**Broker comparison:**

| Feature | Kafka | RabbitMQ | NATS |
|---------|-------|----------|------|
| Model | Distributed log | Message broker | Pub/sub with queues |
| Ordering | Per-partition | Per-queue | Per-subject (JetStream) |
| Retention | Time/size-based | Until consumed | JetStream: configurable |
| Throughput | Very high | High | Very high |
| Use case | Event streaming, logs | Task queues, RPC | Microservice messaging |

**Dead letter queues (DLQ):** Messages that cannot be processed after a configurable number of retries are moved to a DLQ. Monitor DLQ depth as a key operational metric. Implement tooling to inspect, replay, or discard DLQ messages.

## Back-Pressure

Back-pressure is a mechanism for flow control that signals upstream producers to slow down when downstream consumers are overwhelmed.

**Without back-pressure:** Unbounded queues grow until memory is exhausted. Requests pile up, latency spikes, and the system crashes or drops requests unpredictably.

**Implementation strategies:**

- **Bounded queues:** Producer blocks or receives an error when the queue is full. The queue size acts as a buffer and a signal.
- **Rate limiting:** Limit the rate of incoming requests. Return 429 (Too Many Requests) with a Retry-After header.
- **Load shedding:** Intentionally drop requests under extreme load. Prioritize important requests (e.g., payment confirmation over analytics tracking).
- **Reactive streams:** Protocols like gRPC flow control, TCP window size, and Reactive Streams specification provide built-in back-pressure signaling.
- **Adaptive concurrency:** Dynamically adjust the number of concurrent requests based on observed latency and error rate. Libraries: Netflix concurrency-limits.

**Priority queues:** Under load, process high-priority items first and shed low-priority items. Define priority levels (critical, high, normal, low) and allocate capacity accordingly.

## Leader Election

Leader election selects a single node to coordinate an activity. Only one node should be the leader at any time to avoid split-brain scenarios.

**Approaches:**

- **Consensus-based:** Use Raft or Paxos via etcd, ZooKeeper, or Consul. Most robust. Leader holds a lease that must be renewed periodically.
- **Database-based:** Use a row-level lock or a unique constraint in a shared database. Simple but the database is a single point of failure.
- **Cloud-native:** AWS DynamoDB lock client, Google Cloud Spanner leader election, Azure Blob Storage leases.

**Fencing tokens:** After a leader election, the new leader receives a monotonically increasing token. Any operation initiated by an old leader with a lower token is rejected by the data store. Prevents stale leaders from corrupting data.
