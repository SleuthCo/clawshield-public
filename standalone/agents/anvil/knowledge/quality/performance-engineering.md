---
framework: "Performance Engineering"
version: "1.0"
domain: "Software Quality"
agent: "friday"
tags: ["performance", "load-testing", "profiling", "benchmarking", "optimization", "caching"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Performance Engineering

## Performance Testing Types

**Load testing:** Verify system behavior under expected load. Simulate the anticipated number of concurrent users or requests per second. Confirm that response times and error rates stay within acceptable thresholds at target load.

**Stress testing:** Push the system beyond its expected capacity to find the breaking point. Gradually increase load until the system degrades or fails. Identify failure modes: does it degrade gracefully (slower responses) or catastrophically (crashes, data loss)?

**Soak testing (endurance testing):** Run the system under sustained load for an extended period (hours or days). Detect memory leaks, connection pool exhaustion, log file growth, and other issues that only manifest over time.

**Spike testing:** Subject the system to sudden, extreme load increases. Verify that autoscaling kicks in, circuit breakers activate, and the system recovers when the spike subsides.

**Capacity testing:** Determine the maximum capacity of the system. How many users, requests per second, or data volume can it handle before SLOs are breached? Feeds into capacity planning.

**Tools:** k6 (JavaScript-based, developer-friendly), Locust (Python), Gatling (Scala), JMeter (Java, GUI-based), Artillery (Node.js).

**k6 example:**

```javascript
import http from "k6/http";
import { check, sleep } from "k6";

export const options = {
  stages: [
    { duration: "2m", target: 100 },  // Ramp up to 100 VUs
    { duration: "5m", target: 100 },  // Hold at 100 VUs
    { duration: "2m", target: 200 },  // Ramp up to 200 VUs
    { duration: "5m", target: 200 },  // Hold at 200 VUs
    { duration: "2m", target: 0 },    // Ramp down
  ],
  thresholds: {
    http_req_duration: ["p(95)<200", "p(99)<500"],  // 95th percentile < 200ms
    http_req_failed: ["rate<0.01"],                   // Error rate < 1%
  },
};

export default function () {
  const res = http.get("https://api.example.com/users");
  check(res, {
    "status is 200": (r) => r.status === 200,
    "response time < 200ms": (r) => r.timings.duration < 200,
  });
  sleep(1);
}
```

## Profiling Techniques

Profiling identifies where time and resources are spent. Profile before optimizing; do not guess.

**CPU profiling:** Identify which functions consume the most CPU time. Sampling profilers take periodic snapshots of the call stack. Instrumentation profilers measure every function call (higher overhead).

- **Node.js:** `node --prof`, Chrome DevTools, `clinic.js doctor`, `0x` for flame graphs.
- **Python:** `cProfile`, `py-spy` (sampling, low overhead), `scalene` (CPU + memory + GPU).
- **Go:** `pprof` (built-in). `go tool pprof http://localhost:6060/debug/pprof/profile`.
- **Rust:** `cargo flamegraph`, `perf`, `samply`.

**Memory profiling:** Identify memory leaks, excessive allocations, and large objects.

- **Node.js:** `--inspect` with Chrome DevTools heap snapshots, `clinic.js heapprofiler`.
- **Python:** `tracemalloc`, `objgraph`, `memory_profiler`.
- **Go:** `pprof` heap profile. `go tool pprof http://localhost:6060/debug/pprof/heap`.

**Flame graphs:** Visualize profiling data as nested rectangles where width represents time spent. The x-axis shows the call stack (widest = most time), the y-axis shows stack depth. Use flame graphs to quickly identify hot paths.

**When to profile:**

- Before optimizing (measure first, do not guess).
- When a service consistently violates SLOs.
- After deploying a new version with performance regression.
- During capacity planning to identify bottlenecks.

## Benchmarking

Benchmarks measure the performance of specific operations in isolation. They are repeatable, controlled experiments.

**Microbenchmarking principles:**

- Warm up the JIT compiler / runtime before measuring.
- Run enough iterations for statistical significance.
- Control for variance: disable CPU frequency scaling, close other applications, pin to a core.
- Measure the right thing: if you are benchmarking serialization, do not include IO in the measurement.
- Report p50, p95, p99, and standard deviation, not just the average.

**Go benchmarks (built-in):**

```go
func BenchmarkParseJSON(b *testing.B) {
    data := []byte(`{"name":"Alice","age":30}`)
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        var user User
        json.Unmarshal(data, &user)
    }
}

// Run: go test -bench=BenchmarkParseJSON -benchmem
// Output: BenchmarkParseJSON-8  1234567  890 ns/op  256 B/op  4 allocs/op
```

**Continuous benchmarking:** Run benchmarks in CI and track performance over time. Alert on regressions. Tools: bencher.dev, codspeed, GitHub Actions with benchmark comparison.

## Memory Optimization

**Reduce allocations:** Allocations trigger garbage collection. Reuse objects, use object pools, pre-allocate slices/arrays to known sizes.

```go
// Bad: allocates on every call
func processItems(items []Item) []Result {
    results := []Result{} // grows dynamically
    for _, item := range items {
        results = append(results, transform(item))
    }
    return results
}

// Good: pre-allocate
func processItems(items []Item) []Result {
    results := make([]Result, 0, len(items)) // pre-allocate capacity
    for _, item := range items {
        results = append(results, transform(item))
    }
    return results
}
```

**Avoid memory leaks in managed languages:**

- Close event listeners and subscriptions when components unmount.
- Clear intervals and timeouts.
- Avoid closures that capture large objects unnecessarily.
- Use WeakRef / WeakMap for caches that should not prevent garbage collection.
- In Go, be cautious with goroutines: a goroutine that blocks forever leaks its stack and any references it holds.

**Data structure selection:** Use the right data structure for the access pattern. Arrays for sequential access, hash maps for key-based lookup, trees for sorted data, bloom filters for membership testing.

**String optimization:** Strings are immutable in most languages. Repeated concatenation creates many intermediate objects. Use StringBuilder (Java), strings.Builder (Go), join() (Python), or template literals for building strings.

## Database Query Optimization

**Indexing strategy:**

- Create indexes for columns used in WHERE clauses, JOIN conditions, and ORDER BY.
- Use composite indexes for multi-column queries. Column order matters: put equality conditions first, then range conditions.
- Covering indexes include all columns needed by the query, eliminating table lookups.
- Do not over-index: each index slows writes and consumes storage. Monitor unused indexes.

**Analyzing query performance:**

```sql
-- PostgreSQL
EXPLAIN ANALYZE SELECT * FROM orders
WHERE customer_id = 'cust_123'
AND status = 'pending'
ORDER BY created_at DESC
LIMIT 20;

-- Look for:
-- Sequential scans on large tables (need an index)
-- High actual rows vs estimated rows (stale statistics, run ANALYZE)
-- Nested loop joins with large inner tables (consider hash/merge join)
-- Sort operations on unindexed columns
```

**N+1 query problem:** Fetching a list of items, then fetching related data for each item individually. Solution: use JOINs, subqueries, or batch loading (DataLoader pattern).

```sql
-- N+1 problem (1 query for orders + N queries for customers)
SELECT * FROM orders WHERE status = 'pending';
-- For each order: SELECT * FROM customers WHERE id = ?;

-- Solution: JOIN
SELECT o.*, c.name, c.email
FROM orders o
JOIN customers c ON o.customer_id = c.id
WHERE o.status = 'pending';
```

**Connection pooling:** Establish a pool of database connections that are reused across requests. Creating a new connection for each request adds significant latency (TCP handshake, TLS, authentication). Configure pool size based on workload: too small limits concurrency, too large overwhelms the database.

## Caching Strategies

**What to cache:** Expensive computations, frequently accessed data that changes infrequently, external API responses, rendered templates, session data.

**What not to cache:** Rapidly changing data, security-sensitive data (tokens, sessions -- if cached, use short TTLs), data that must be strictly consistent.

**Cache key design:** Include all parameters that affect the result. Use a prefix for namespacing: `users:usr_123:profile`. Include a version for cache invalidation: `v2:users:usr_123:profile`.

**TTL selection:** Balance freshness against load. Start with conservative TTLs and loosen as you gain confidence. Hot data: 30-60 seconds. Reference data: 5-60 minutes. Static data: hours or days.

**Cache stampede prevention:** When a popular cache entry expires, many concurrent requests hit the database simultaneously. Mitigations:

- **Lock/mutex:** Only one request refreshes the cache; others wait.
- **Stale-while-revalidate:** Serve the stale value while refreshing in the background.
- **Probabilistic early expiration:** Each request has a small chance of refreshing the cache before expiration, spreading the refresh load.

**Distributed cache (Redis) patterns:**

```python
# Cache-aside with TTL
async def get_user(user_id: str) -> User:
    cached = await redis.get(f"users:{user_id}")
    if cached:
        return User.model_validate_json(cached)

    user = await db.fetch_user(user_id)
    if user:
        await redis.set(f"users:{user_id}", user.model_dump_json(), ex=300)
    return user

# Invalidate on write
async def update_user(user_id: str, data: UpdateUser) -> User:
    user = await db.update_user(user_id, data)
    await redis.delete(f"users:{user_id}")
    return user
```

## Lazy Loading

Lazy loading defers initialization or loading of resources until they are actually needed. It reduces startup time and memory usage.

**Application-level lazy loading:**

- Load configuration on first access, not at startup.
- Initialize database connections when the first query runs.
- Use lazy imports in Python (`importlib.import_module` on demand).

**Frontend lazy loading:**

- Code splitting: load JavaScript modules on demand (`React.lazy`, dynamic `import()`).
- Image lazy loading: load images when they scroll into the viewport (`loading="lazy"`).
- Infinite scroll: load more items as the user scrolls.

**Database lazy loading (ORM):**

- Load related entities only when accessed (lazy relationships).
- Risk: N+1 queries. Use eager loading (JOIN) when you know you will need the related data.
- Best practice: default to lazy loading, opt into eager loading for specific queries.

**Connection pool lazy initialization:** Create connections on demand up to the pool maximum rather than pre-creating all connections at startup. This reduces resource usage when the application is under low load.

## Performance Budgets

A performance budget sets concrete limits on performance metrics. It prevents gradual degradation by making performance a first-class concern.

**Budget types:**

- **Response time:** p95 < 200ms for API endpoints.
- **Bundle size:** JavaScript bundle < 200KB gzipped.
- **Time to Interactive:** < 3 seconds on a 3G connection.
- **Database queries per request:** < 10 queries per API call.
- **Memory usage:** Service RSS < 512MB under normal load.

**Enforcement:** Measure budgets in CI. Fail the build if a budget is exceeded. Track trends over time. Alert when metrics approach the budget limit.
