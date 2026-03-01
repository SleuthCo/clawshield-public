---
framework: "TypeScript"
version: "1.0"
domain: "Programming Languages"
agent: "friday"
tags: ["typescript", "type-system", "generics", "patterns", "strict-mode"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Advanced TypeScript Patterns

## Generics and Generic Constraints

Generics allow writing reusable, type-safe abstractions. Always prefer the narrowest constraint that satisfies your use case.

```typescript
// Basic generic constraint
function getProperty<T, K extends keyof T>(obj: T, key: K): T[K] {
  return obj[key];
}

// Generic with multiple constraints
function merge<T extends object, U extends object>(a: T, b: U): T & U {
  return { ...a, ...b };
}

// Generic class with constraint
class Repository<T extends { id: string }> {
  private items: Map<string, T> = new Map();

  save(item: T): void {
    this.items.set(item.id, item);
  }

  findById(id: string): T | undefined {
    return this.items.get(id);
  }
}

// Generic factory pattern
function createInstance<T>(ctor: new (...args: any[]) => T, ...args: any[]): T {
  return new ctor(...args);
}
```

Default generic parameters reduce boilerplate at call sites:

```typescript
interface PaginatedResponse<T, M = { total: number; page: number }> {
  data: T[];
  meta: M;
}

// Uses default meta type
const response: PaginatedResponse<User> = { data: [], meta: { total: 0, page: 1 } };
```

## Conditional Types

Conditional types enable type-level branching logic. They follow the syntax `T extends U ? X : Y`.

```typescript
// Extract return type of async functions
type UnwrapPromise<T> = T extends Promise<infer U> ? U : T;

// Recursive unwrapping
type DeepUnwrap<T> = T extends Promise<infer U> ? DeepUnwrap<U> : T;

// Distributive conditional types (distributes over unions)
type NonNullableFields<T> = {
  [K in keyof T]: T[K] extends null | undefined ? never : K;
}[keyof T];

// Exclude certain properties by value type
type StringKeysOf<T> = {
  [K in keyof T]: T[K] extends string ? K : never;
}[keyof T];

// Conditional type with infer for function parameter extraction
type FirstParam<T> = T extends (first: infer P, ...rest: any[]) => any ? P : never;

// Practical example: API response handling
type ApiResponse<T> = T extends { error: infer E }
  ? { success: false; error: E }
  : { success: true; data: T };
```

## Template Literal Types

Template literal types enable string manipulation at the type level. Introduced in TypeScript 4.1, they are powerful for creating typed string patterns.

```typescript
// Event handler naming
type EventName = "click" | "focus" | "blur";
type EventHandler = `on${Capitalize<EventName>}`; // "onClick" | "onFocus" | "onBlur"

// Route parameters
type ExtractParams<T extends string> =
  T extends `${string}:${infer Param}/${infer Rest}`
    ? Param | ExtractParams<Rest>
    : T extends `${string}:${infer Param}`
    ? Param
    : never;

type RouteParams = ExtractParams<"/users/:userId/posts/:postId">; // "userId" | "postId"

// CSS unit types
type CSSUnit = "px" | "em" | "rem" | "vh" | "vw" | "%";
type CSSValue = `${number}${CSSUnit}`;

// Dot-notation paths for nested objects
type DotPath<T, Prefix extends string = ""> = T extends object
  ? {
      [K in keyof T & string]: T[K] extends object
        ? DotPath<T[K], `${Prefix}${K}.`> | `${Prefix}${K}`
        : `${Prefix}${K}`;
    }[keyof T & string]
  : never;
```

## Discriminated Unions

Discriminated unions (tagged unions) are the idiomatic TypeScript way to model sum types. They require a shared literal-type discriminant property.

```typescript
// State machine modeling
type RequestState<T> =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "success"; data: T }
  | { status: "error"; error: Error };

function handleState<T>(state: RequestState<T>): string {
  switch (state.status) {
    case "idle":
      return "Waiting...";
    case "loading":
      return "Loading...";
    case "success":
      return `Got ${JSON.stringify(state.data)}`; // data is narrowed
    case "error":
      return `Error: ${state.error.message}`; // error is narrowed
  }
}

// Exhaustive checking with never
function assertNever(value: never): never {
  throw new Error(`Unexpected value: ${value}`);
}

// Domain event modeling
type DomainEvent =
  | { type: "UserCreated"; userId: string; email: string }
  | { type: "UserDeleted"; userId: string }
  | { type: "UserUpdated"; userId: string; changes: Partial<User> };

function handleEvent(event: DomainEvent): void {
  switch (event.type) {
    case "UserCreated":
      console.log(event.email); // narrowed correctly
      break;
    case "UserDeleted":
      break;
    case "UserUpdated":
      console.log(event.changes);
      break;
    default:
      assertNever(event); // compile error if a case is missed
  }
}
```

## Type Guards and Type Narrowing

Type guards narrow types within conditional blocks. Prefer user-defined type guards over type assertions.

```typescript
// User-defined type guard with `is`
function isString(value: unknown): value is string {
  return typeof value === "string";
}

// Assertion function (narrows in current scope, throws on failure)
function assertDefined<T>(value: T | null | undefined, msg?: string): asserts value is T {
  if (value === null || value === undefined) {
    throw new Error(msg ?? "Value is not defined");
  }
}

// Discriminated union guard
function isSuccessResponse<T>(
  response: RequestState<T>
): response is Extract<RequestState<T>, { status: "success" }> {
  return response.status === "success";
}

// `in` operator narrowing
interface Cat { meow(): void; }
interface Dog { bark(): void; }

function speak(animal: Cat | Dog) {
  if ("meow" in animal) {
    animal.meow(); // narrowed to Cat
  } else {
    animal.bark(); // narrowed to Dog
  }
}

// Combining guards with filter
const items: (string | number)[] = [1, "a", 2, "b"];
const strings: string[] = items.filter((x): x is string => typeof x === "string");
```

## Branded Types (Nominal Typing)

TypeScript uses structural typing, but branded types simulate nominal typing to prevent mixing semantically different values that share the same underlying type.

```typescript
// Brand pattern using intersection with unique symbol
declare const brand: unique symbol;
type Brand<T, B> = T & { readonly [brand]: B };

type UserId = Brand<string, "UserId">;
type OrderId = Brand<string, "OrderId">;
type Email = Brand<string, "Email">;

// Smart constructors validate at the boundary
function createUserId(raw: string): UserId {
  if (!raw.startsWith("usr_")) throw new Error("Invalid user ID");
  return raw as UserId;
}

function createEmail(raw: string): Email {
  if (!raw.includes("@")) throw new Error("Invalid email");
  return raw as Email;
}

// Now the compiler prevents mixing
function sendEmail(to: Email, userId: UserId): void { /* ... */ }

const uid = createUserId("usr_abc");
const email = createEmail("test@example.com");

sendEmail(email, uid);    // OK
// sendEmail(uid, email); // Compile error: types are incompatible

// Branded numeric types for units
type Meters = Brand<number, "Meters">;
type Seconds = Brand<number, "Seconds">;
type MetersPerSecond = Brand<number, "MetersPerSecond">;

function velocity(distance: Meters, time: Seconds): MetersPerSecond {
  return (distance / time) as MetersPerSecond;
}
```

## Module Augmentation and Declaration Merging

Module augmentation extends existing modules with additional types without modifying source code. Declaration merging combines multiple declarations of the same entity.

```typescript
// Augmenting a third-party module (e.g., Express)
declare module "express" {
  interface Request {
    user?: { id: string; role: string };
    correlationId: string;
  }
}

// Augmenting global scope
declare global {
  interface Window {
    __APP_CONFIG__: { apiUrl: string; version: string };
  }
}

// Interface declaration merging (same-name interfaces merge automatically)
interface Config {
  database: { host: string; port: number };
}

interface Config {
  cache: { ttl: number };
}

// Merged: Config has both database and cache

// Enum merging with namespace
enum Direction {
  Up = "UP",
  Down = "DOWN",
}

namespace Direction {
  export function parse(raw: string): Direction {
    const upper = raw.toUpperCase();
    if (upper === "UP") return Direction.Up;
    if (upper === "DOWN") return Direction.Down;
    throw new Error(`Unknown direction: ${raw}`);
  }
}

Direction.parse("up"); // Direction.Up
```

## Strict Mode Best Practices

Enable all strict flags in `tsconfig.json`. Each flag catches a category of bugs at compile time.

```jsonc
{
  "compilerOptions": {
    "strict": true,                    // Enables all strict flags below
    "noUncheckedIndexedAccess": true,  // Array/object index returns T | undefined
    "exactOptionalProperties": true,   // Distinguishes missing vs. undefined
    "noPropertyAccessFromIndexSignature": true, // Forces bracket notation for index sigs
    "noFallthroughCasesInSwitch": true,
    "forceConsistentCasingInFileNames": true
  }
}
```

Key strict-mode patterns:

```typescript
// strictNullChecks: handle null/undefined explicitly
function findUser(id: string): User | undefined {
  return db.get(id); // caller must check for undefined
}

// noUncheckedIndexedAccess: array access returns T | undefined
const arr = [1, 2, 3];
const val = arr[0]; // number | undefined -- must narrow before using

// strictFunctionTypes: function parameter types are checked contravariantly
type Handler = (event: MouseEvent) => void;
// Cannot assign (event: Event) => void to Handler (would be unsafe)

// strictPropertyInitialization: all properties must be initialized
class Service {
  private client: HttpClient;

  constructor(client: HttpClient) {
    this.client = client; // must initialize in constructor
  }
}

// Use definite assignment assertion only when you can guarantee initialization
class LazyService {
  private client!: HttpClient; // `!` asserts it will be assigned before use

  initialize(client: HttpClient) {
    this.client = client;
  }
}
```

## Utility Types and Advanced Mapped Types

TypeScript ships with powerful built-in utility types. Understanding them enables construction of sophisticated custom mapped types.

```typescript
// Deep partial (recursive)
type DeepPartial<T> = {
  [K in keyof T]?: T[K] extends object ? DeepPartial<T[K]> : T[K];
};

// Deep readonly (recursive)
type DeepReadonly<T> = {
  readonly [K in keyof T]: T[K] extends object ? DeepReadonly<T[K]> : T[K];
};

// Pick by value type
type PickByValue<T, V> = {
  [K in keyof T as T[K] extends V ? K : never]: T[K];
};

// Mutable (remove readonly)
type Mutable<T> = {
  -readonly [K in keyof T]: T[K];
};

// Type-safe object entries
type Entries<T> = {
  [K in keyof T]: [K, T[K]];
}[keyof T][];

function typedEntries<T extends object>(obj: T): Entries<T> {
  return Object.entries(obj) as Entries<T>;
}

// Builder pattern with type accumulation
class QueryBuilder<Selected extends string = never> {
  select<F extends string>(field: F): QueryBuilder<Selected | F> {
    return this as any;
  }

  execute(): Record<Selected, unknown> {
    return {} as any;
  }
}

const result = new QueryBuilder().select("name").select("age").execute();
// result is Record<"name" | "age", unknown>
```

## Variance Annotations (TypeScript 4.7+)

Explicit variance annotations on generic type parameters improve type-checking performance and document intent.

```typescript
// `out` = covariant (producer), `in` = contravariant (consumer)
interface Producer<out T> {
  get(): T;
}

interface Consumer<in T> {
  accept(value: T): void;
}

interface Transform<in I, out O> {
  process(input: I): O;
}
```

Variance annotations have no runtime effect but help the compiler catch unsafe assignments earlier and more clearly.

## The `satisfies` Operator (TypeScript 4.9+)

The `satisfies` operator validates that an expression matches a type without widening or narrowing the inferred type.

```typescript
type ColorConfig = Record<string, [number, number, number] | string>;

const colors = {
  red: [255, 0, 0],
  green: "#00FF00",
  blue: [0, 0, 255],
} satisfies ColorConfig;

// Inferred type preserves literal types:
colors.red;   // [number, number, number] -- not string | [number, number, number]
colors.green; // string -- not string | [number, number, number]

// Useful for configuration objects
const config = {
  port: 3000,
  host: "localhost",
  debug: false,
} satisfies Record<string, string | number | boolean>;

// config.port is inferred as number (not string | number | boolean)
```
