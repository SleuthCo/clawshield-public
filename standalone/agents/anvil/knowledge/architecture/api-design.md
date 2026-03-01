---
framework: "API Design"
version: "1.0"
domain: "Software Architecture"
agent: "friday"
tags: ["api", "rest", "graphql", "grpc", "openapi", "versioning", "pagination"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# API Design

## REST Maturity Model (Richardson Maturity Model)

The Richardson Maturity Model defines four levels of REST compliance. Most production APIs target Level 2; Level 3 (HATEOAS) is aspirational for most teams.

**Level 0 -- The Swamp of POX:** Single endpoint, single HTTP method (usually POST). RPC over HTTP. Example: SOAP-style `POST /api` with operation in the body.

**Level 1 -- Resources:** Individual URIs for resources. `POST /users`, `POST /orders/123/cancel`. Still uses POST for everything, but resources are addressable.

**Level 2 -- HTTP Verbs:** Proper use of HTTP methods. `GET /users/123` to read, `POST /users` to create, `PUT /users/123` to replace, `PATCH /users/123` to partial update, `DELETE /users/123` to remove. Uses HTTP status codes meaningfully. This is the standard for most REST APIs.

**Level 3 -- Hypermedia Controls (HATEOAS):** Responses include links to related actions and resources. The client navigates the API by following links rather than constructing URLs. Rarely implemented fully but valuable for discoverability.

**Resource naming conventions:**

- Use nouns, not verbs: `/orders` not `/getOrders`.
- Plural nouns for collections: `/users`, `/users/123`.
- Nested resources for relationships: `/users/123/orders`.
- Limit nesting depth to two levels: `/users/123/orders/456` is fine; deeper nesting suggests the nested resource should be top-level.
- Use kebab-case for multi-word resources: `/line-items`.

**HTTP status code usage:**

| Code | Meaning | When to Use |
|------|---------|-------------|
| 200 | OK | Successful GET, PUT, PATCH |
| 201 | Created | Successful POST that creates a resource |
| 204 | No Content | Successful DELETE |
| 400 | Bad Request | Malformed request body or parameters |
| 401 | Unauthorized | Missing or invalid authentication |
| 403 | Forbidden | Authenticated but not authorized |
| 404 | Not Found | Resource does not exist |
| 409 | Conflict | State conflict (duplicate, version mismatch) |
| 422 | Unprocessable Entity | Valid syntax but semantic errors (validation) |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Unexpected server failure |
| 503 | Service Unavailable | Server temporarily overloaded or in maintenance |

## GraphQL Schema Design

GraphQL provides a single endpoint with a typed schema. Clients request exactly the fields they need, avoiding over-fetching and under-fetching.

**Schema design principles:**

```graphql
type Query {
  user(id: ID!): User
  users(filter: UserFilter, pagination: PaginationInput): UserConnection!
  order(id: ID!): Order
}

type Mutation {
  createUser(input: CreateUserInput!): CreateUserPayload!
  updateUser(id: ID!, input: UpdateUserInput!): UpdateUserPayload!
  deleteUser(id: ID!): DeleteUserPayload!
}

type User {
  id: ID!
  name: String!
  email: String!
  orders(first: Int, after: String): OrderConnection!
  createdAt: DateTime!
}

# Input types for mutations (separate from output types)
input CreateUserInput {
  name: String!
  email: String!
}

# Payload types with union for errors
type CreateUserPayload {
  user: User
  errors: [UserError!]!
}

type UserError {
  field: String
  message: String!
  code: ErrorCode!
}

# Relay-style connection for pagination
type UserConnection {
  edges: [UserEdge!]!
  pageInfo: PageInfo!
  totalCount: Int!
}

type UserEdge {
  node: User!
  cursor: String!
}

type PageInfo {
  hasNextPage: Boolean!
  hasPreviousPage: Boolean!
  startCursor: String
  endCursor: String
}
```

**Best practices:**

- Use input types for mutations, never reuse output types as inputs.
- Return payload types from mutations that include both the result and potential errors.
- Use Relay-style connections for paginated lists.
- Design for the client, not the database schema. GraphQL types should map to UI needs.
- Implement DataLoader pattern to batch and cache database queries within a single request, solving the N+1 problem.
- Limit query depth and complexity to prevent abuse. Use persisted queries in production.

## gRPC and Protocol Buffers

gRPC is a high-performance RPC framework using Protocol Buffers for serialization. It excels at service-to-service communication where performance and strong typing matter.

**Proto file design:**

```protobuf
syntax = "proto3";

package order.v1;

service OrderService {
  // Unary RPC
  rpc GetOrder(GetOrderRequest) returns (GetOrderResponse);

  // Server streaming
  rpc WatchOrderStatus(WatchOrderRequest) returns (stream OrderStatusUpdate);

  // Client streaming
  rpc UploadLineItems(stream LineItem) returns (UploadSummary);

  // Bidirectional streaming
  rpc Chat(stream ChatMessage) returns (stream ChatMessage);
}

message GetOrderRequest {
  string order_id = 1;
}

message GetOrderResponse {
  Order order = 1;
}

message Order {
  string id = 1;
  string customer_id = 2;
  repeated LineItem items = 3;
  OrderStatus status = 4;
  google.protobuf.Timestamp created_at = 5;
  Money total = 6;
}

enum OrderStatus {
  ORDER_STATUS_UNSPECIFIED = 0;
  ORDER_STATUS_PENDING = 1;
  ORDER_STATUS_CONFIRMED = 2;
  ORDER_STATUS_SHIPPED = 3;
  ORDER_STATUS_DELIVERED = 4;
  ORDER_STATUS_CANCELLED = 5;
}

message Money {
  int64 amount_micros = 1;  // Amount in micros (1/1,000,000 of currency unit)
  string currency_code = 2;  // ISO 4217
}
```

**gRPC best practices:**

- Use `UNSPECIFIED = 0` as the first enum value for forward compatibility.
- Never reuse field numbers, even for deleted fields. Use `reserved` to prevent accidental reuse.
- Use `google.protobuf.Timestamp` for times, not int64 or string.
- Represent money as integer micros, not floating point.
- Version packages: `order.v1`, `order.v2`.
- Use streaming RPCs for real-time data, large payloads, or long-running operations.

## API Versioning

API versioning strategies have different trade-offs. Choose one approach and apply it consistently.

**URL path versioning:** `/v1/users`, `/v2/users`. Most explicit, easiest to implement and test. Cache-friendly. Recommended for most public APIs.

**Header versioning:** `Accept: application/vnd.myapi.v2+json`. More "pure" REST. Harder to test casually (cannot simply change the URL in a browser).

**Query parameter versioning:** `/users?version=2`. Simple but can be confused with resource parameters. Less common.

**Content negotiation:** `Accept: application/json; version=2`. Similar trade-offs to header versioning.

**Breaking vs. non-breaking changes:**

- Non-breaking (additive): Adding new fields, new endpoints, new optional parameters. No version bump needed.
- Breaking: Removing fields, renaming fields, changing field types, changing endpoint URLs, changing required parameters. Requires a new version.

**Deprecation strategy:** Announce deprecation with a timeline (minimum 6 months for public APIs). Return `Deprecation` and `Sunset` headers. Log usage of deprecated endpoints to track migration progress. Maintain at most two active versions (current and previous).

## Pagination

Pagination prevents unbounded responses and is essential for any list endpoint.

**Cursor-based pagination (recommended):** Use an opaque cursor (typically a base64-encoded identifier) to mark position. Efficient even on large datasets because it does not require counting offsets.

```json
GET /users?limit=20&after=eyJpZCI6MTIzfQ

{
  "data": [...],
  "pagination": {
    "has_next": true,
    "next_cursor": "eyJpZCI6MTQzfQ",
    "has_previous": true,
    "previous_cursor": "eyJpZCI6MTI0fQ"
  }
}
```

**Offset-based pagination:** `?page=3&per_page=50`. Simpler to implement and allows jumping to arbitrary pages. Performance degrades on large tables because the database must scan and skip rows. Inconsistent when data is inserted or deleted between pages.

**Keyset pagination:** Similar to cursor-based but uses a known column value (e.g., `?created_after=2024-01-01T00:00:00Z&limit=50`). Transparent and efficient. Works well when there is a natural ordering column.

**Guidelines:** Always set a maximum page size (e.g., 100). Return `total_count` only if the client needs it and it can be computed efficiently. Include pagination metadata in every list response.

## Rate Limiting

Rate limiting protects APIs from abuse and ensures fair resource allocation.

**Algorithms:**

- **Fixed window:** Count requests per fixed time window (e.g., 1000 requests per minute). Simple but allows burst at window boundaries.
- **Sliding window:** Weighted combination of current and previous window counts. Smooths burst behavior.
- **Token bucket:** Bucket holds tokens, requests consume tokens, tokens refill at a fixed rate. Allows short bursts up to bucket capacity.
- **Leaky bucket:** Requests enter a queue that drains at a fixed rate. Smoothest output rate but adds latency.

**Response headers:**

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 742
X-RateLimit-Reset: 1640995200
Retry-After: 30
```

**Tiered limits:** Different limits for different authentication levels (anonymous, authenticated, premium). Different limits for different endpoint categories (reads vs. writes, search vs. CRUD).

## HATEOAS

Hypermedia as the Engine of Application State means API responses include links that tell the client what actions are available next.

```json
{
  "id": "order_123",
  "status": "pending",
  "total": 99.99,
  "_links": {
    "self": { "href": "/orders/order_123" },
    "cancel": { "href": "/orders/order_123/cancel", "method": "POST" },
    "pay": { "href": "/orders/order_123/pay", "method": "POST" },
    "items": { "href": "/orders/order_123/items" }
  }
}
```

When the order is already paid, the response would omit the `pay` link and might include a `refund` link instead. The client discovers available actions from the response rather than hard-coding state transitions.

**Practical adoption:** Full HATEOAS is rare in practice. A pragmatic approach is to include `self` links on all resources and action links for state transitions. Use JSON:API or HAL format for consistency.

## OpenAPI Specification

OpenAPI (formerly Swagger) is the standard for describing REST APIs. Use it for documentation, client generation, server stub generation, and contract testing.

**API-first development workflow:**

1. Design the OpenAPI spec collaboratively (API designers, frontend, backend).
2. Review the spec in a pull request. Use linters (Spectral, Redocly) to enforce standards.
3. Generate server stubs and client SDKs from the spec.
4. Implement the server to match the spec.
5. Run contract tests to verify the implementation matches the spec.
6. Generate documentation from the spec (Redoc, Swagger UI).

**Spec quality checklist:**

- Every endpoint has a description and at least one example response.
- All error responses are documented with their schemas.
- Parameters have descriptions, types, and constraints (min, max, pattern).
- Use `$ref` for shared schemas to avoid duplication.
- Security schemes are defined and applied.
- Tags organize endpoints into logical groups.

## API-First Development

In API-first development, the API contract is designed before implementation begins. The spec serves as the single source of truth for both producers and consumers.

**Benefits:** Frontend and backend can develop in parallel (frontend uses mocked responses from the spec). Breaking changes are caught during design review, not after implementation. Client SDKs are always in sync with the API.

**Mocking:** Use tools like Prism or Mockoon to run a mock server from the OpenAPI spec. Frontend teams develop against the mock while the backend is being built.

**Contract testing:** The spec becomes a contract. Both sides are tested against it. Tools: Schemathesis (generates tests from OpenAPI spec), Dredd, committee (Ruby). This catches drift between the spec and the implementation.
