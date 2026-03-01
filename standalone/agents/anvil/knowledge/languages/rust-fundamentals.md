---
framework: "Rust"
version: "1.0"
domain: "Programming Languages"
agent: "friday"
tags: ["rust", "ownership", "borrowing", "lifetimes", "traits", "async", "safety"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Rust Fundamentals

## Ownership and Borrowing

Rust enforces memory safety at compile time through its ownership system. Every value has exactly one owner, and when the owner goes out of scope the value is dropped.

```rust
// Ownership transfer (move)
fn main() {
    let s1 = String::from("hello");
    let s2 = s1;          // s1 is moved to s2; s1 is no longer valid
    // println!("{s1}");   // compile error: value used after move

    // Clone for explicit deep copy
    let s3 = s2.clone();
    println!("{s2} {s3}"); // both valid

    // Copy types (stack-only, implement Copy trait): i32, f64, bool, char, tuples of Copy types
    let x = 42;
    let y = x;             // copy, not move
    println!("{x} {y}");   // both valid
}

// Ownership in function calls
fn take_ownership(s: String) {
    println!("{s}");
} // s is dropped here

fn give_ownership() -> String {
    String::from("gift")
} // ownership transferred to caller
```

Borrowing rules: at any given time, you can have either one mutable reference OR any number of immutable references. References must always be valid (no dangling).

```rust
fn calculate_length(s: &str) -> usize {
    s.len()
}

fn append_exclaim(s: &mut String) {
    s.push('!');
}

fn main() {
    let mut greeting = String::from("Hello");

    // Multiple immutable borrows are fine
    let r1 = &greeting;
    let r2 = &greeting;
    println!("{r1} {r2}");

    // Mutable borrow after immutable borrows are done (NLL - Non-Lexical Lifetimes)
    let r3 = &mut greeting;
    r3.push_str(" world");

    // Cannot have mutable and immutable borrows at the same time
    // let r4 = &greeting;  // error if r3 is still in use
}
```

## Lifetimes

Lifetimes are the compiler's way of tracking how long references are valid. Most lifetimes are inferred; explicit annotations are needed when the compiler cannot determine the relationship.

```rust
// Explicit lifetime annotations
fn longest<'a>(x: &'a str, y: &'a str) -> &'a str {
    if x.len() > y.len() { x } else { y }
}

// The returned reference lives at least as long as the shorter of x and y

// Lifetime in structs: the struct cannot outlive the reference it holds
struct Excerpt<'a> {
    text: &'a str,
}

impl<'a> Excerpt<'a> {
    fn level(&self) -> i32 {
        3
    }

    // Lifetime elision: &self lifetime is applied to return
    fn announce(&self, announcement: &str) -> &str {
        println!("Attention: {announcement}");
        self.text
    }
}

// Multiple lifetimes
fn first_word<'a, 'b>(s: &'a str, _prefix: &'b str) -> &'a str {
    s.split_whitespace().next().unwrap_or(s)
}

// 'static lifetime: lives for the entire program duration
let s: &'static str = "I live forever";

// Lifetime elision rules (applied automatically):
// 1. Each reference parameter gets its own lifetime
// 2. If exactly one input lifetime, it's assigned to all output lifetimes
// 3. If &self or &mut self, self's lifetime is assigned to outputs
```

## Traits

Traits define shared behavior. They are Rust's primary mechanism for polymorphism and are similar to interfaces in other languages.

```rust
// Defining and implementing traits
trait Summary {
    fn summarize_author(&self) -> String;

    // Default implementation
    fn summarize(&self) -> String {
        format!("(Read more from {}...)", self.summarize_author())
    }
}

struct Article {
    title: String,
    author: String,
    content: String,
}

impl Summary for Article {
    fn summarize_author(&self) -> String {
        self.author.clone()
    }

    fn summarize(&self) -> String {
        format!("{}, by {} - {}", self.title, self.author, &self.content[..50])
    }
}

// Trait bounds
fn notify(item: &impl Summary) {
    println!("Breaking: {}", item.summarize());
}

// Equivalent with explicit trait bound
fn notify_explicit<T: Summary>(item: &T) {
    println!("Breaking: {}", item.summarize());
}

// Multiple bounds
fn display_summary<T: Summary + std::fmt::Display>(item: &T) {
    println!("{item}: {}", item.summarize());
}

// where clause for readability
fn complex_function<T, U>(t: &T, u: &U) -> String
where
    T: Summary + Clone,
    U: std::fmt::Display + std::fmt::Debug,
{
    format!("{}: {u:?}", t.summarize())
}

// Returning impl Trait
fn create_summarizable() -> impl Summary {
    Article {
        title: "AI News".into(),
        author: "Bot".into(),
        content: "Long content here...".repeat(10),
    }
}

// Trait objects for dynamic dispatch
fn print_all(items: &[&dyn Summary]) {
    for item in items {
        println!("{}", item.summarize());
    }
}

// Supertraits
trait PrettyPrint: std::fmt::Display + Summary {
    fn pretty_print(&self) {
        println!("== {} ==\n{}", self.summarize(), self);
    }
}
```

## Enums and Pattern Matching

Rust enums are algebraic data types (sum types). Each variant can hold different data.

```rust
#[derive(Debug)]
enum Shape {
    Circle { radius: f64 },
    Rectangle { width: f64, height: f64 },
    Triangle { base: f64, height: f64 },
    Point,
}

impl Shape {
    fn area(&self) -> f64 {
        match self {
            Shape::Circle { radius } => std::f64::consts::PI * radius * radius,
            Shape::Rectangle { width, height } => width * height,
            Shape::Triangle { base, height } => 0.5 * base * height,
            Shape::Point => 0.0,
        }
    }
}

// Pattern matching is exhaustive; all variants must be handled
fn describe(shape: &Shape) -> String {
    match shape {
        Shape::Circle { radius } if *radius > 10.0 => "Large circle".to_string(),
        Shape::Circle { radius } => format!("Circle r={radius}"),
        Shape::Rectangle { width, height } if width == height => "Square".to_string(),
        Shape::Rectangle { .. } => "Rectangle".to_string(),
        _ => "Other shape".to_string(),
    }
}

// if let for single-variant matching
fn maybe_radius(shape: &Shape) -> Option<f64> {
    if let Shape::Circle { radius } = shape {
        Some(*radius)
    } else {
        None
    }
}

// let-else (Rust 1.65+)
fn get_radius(shape: &Shape) -> f64 {
    let Shape::Circle { radius } = shape else {
        panic!("Expected circle");
    };
    *radius
}

// Nested destructuring
enum Message {
    Quit,
    Move { x: i32, y: i32 },
    Write(String),
    Color(u8, u8, u8),
}

fn process(msg: Message) {
    match msg {
        Message::Move { x, y } if x > 0 && y > 0 => println!("Move to ({x},{y})"),
        Message::Color(r, g, b) => println!("rgb({r},{g},{b})"),
        Message::Write(ref text) if text.is_empty() => println!("Empty write"),
        Message::Write(text) => println!("Write: {text}"),
        _ => {}
    }
}
```

## Error Handling with Result and Option

Rust uses `Result<T, E>` for recoverable errors and `Option<T>` for optional values. The `?` operator propagates errors concisely.

```rust
use std::fs;
use std::io;
use std::num::ParseIntError;

// Custom error type
#[derive(Debug)]
enum AppError {
    Io(io::Error),
    Parse(ParseIntError),
    NotFound(String),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::Io(e) => write!(f, "IO error: {e}"),
            AppError::Parse(e) => write!(f, "Parse error: {e}"),
            AppError::NotFound(s) => write!(f, "Not found: {s}"),
        }
    }
}

impl std::error::Error for AppError {}

// From implementations for automatic conversion with ?
impl From<io::Error> for AppError {
    fn from(e: io::Error) -> Self { AppError::Io(e) }
}

impl From<ParseIntError> for AppError {
    fn from(e: ParseIntError) -> Self { AppError::Parse(e) }
}

// Using ? operator for clean error propagation
fn read_count(path: &str) -> Result<i32, AppError> {
    let content = fs::read_to_string(path)?;   // io::Error -> AppError
    let count = content.trim().parse::<i32>()?; // ParseIntError -> AppError
    Ok(count)
}

// Option combinators
fn find_user(id: u64) -> Option<String> {
    let users = vec!["alice", "bob", "charlie"];
    users.get(id as usize).map(|s| s.to_string())
}

fn user_email(id: u64) -> Option<String> {
    find_user(id)
        .filter(|name| !name.is_empty())
        .map(|name| format!("{name}@example.com"))
}

// thiserror crate (recommended for libraries)
// #[derive(thiserror::Error, Debug)]
// enum AppError {
//     #[error("IO error: {0}")]
//     Io(#[from] io::Error),
//     #[error("Parse error: {0}")]
//     Parse(#[from] ParseIntError),
// }

// anyhow crate (recommended for applications)
// fn main() -> anyhow::Result<()> {
//     let count = read_count("data.txt").context("Failed to read count")?;
//     Ok(())
// }
```

## Async Rust

Async Rust uses `Future`-based concurrency. The most common runtime is Tokio. Futures are lazy; they do nothing until polled by an executor.

```rust
use tokio;

// Basic async function
async fn fetch_data(url: &str) -> Result<String, reqwest::Error> {
    let response = reqwest::get(url).await?;
    response.text().await
}

// Concurrent execution with join!
async fn fetch_both() -> (String, String) {
    let (a, b) = tokio::join!(
        fetch_data("https://api.example.com/a"),
        fetch_data("https://api.example.com/b"),
    );
    (a.unwrap_or_default(), b.unwrap_or_default())
}

// Select first to complete
async fn race_requests() -> String {
    tokio::select! {
        result = fetch_data("https://primary.example.com") => {
            result.unwrap_or_else(|_| "primary failed".into())
        }
        result = fetch_data("https://fallback.example.com") => {
            result.unwrap_or_else(|_| "fallback failed".into())
        }
    }
}

// Spawning tasks
async fn process_batch(urls: Vec<String>) -> Vec<String> {
    let mut handles = Vec::new();
    for url in urls {
        handles.push(tokio::spawn(async move {
            fetch_data(&url).await.unwrap_or_default()
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        results.push(handle.await.unwrap());
    }
    results
}

// Async streams with tokio
use tokio_stream::StreamExt;

async fn process_stream() {
    let mut stream = tokio_stream::iter(vec![1, 2, 3])
        .map(|x| x * 2)
        .filter(|x| *x > 2);

    while let Some(value) = stream.next().await {
        println!("{value}");
    }
}
```

Key pitfall: do not hold a `MutexGuard` (from `std::sync::Mutex`) across `.await` points. Use `tokio::sync::Mutex` if you need a lock held across await, or restructure to release the lock before awaiting.

## Smart Pointers

Smart pointers own the data they point to and provide additional semantics beyond references.

```rust
use std::rc::Rc;
use std::cell::RefCell;
use std::sync::{Arc, Mutex};

// Box<T>: heap allocation with single ownership
let boxed: Box<dyn Summary> = Box::new(article);

// Recursive types require Box
enum List {
    Cons(i32, Box<List>),
    Nil,
}

// Rc<T>: reference-counted shared ownership (single-threaded)
let shared = Rc::new(String::from("shared data"));
let clone1 = Rc::clone(&shared);
let clone2 = Rc::clone(&shared);
println!("ref count: {}", Rc::strong_count(&shared)); // 3

// RefCell<T>: interior mutability (runtime borrow checking)
let data = RefCell::new(vec![1, 2, 3]);
data.borrow_mut().push(4);      // mutable borrow at runtime
println!("{:?}", data.borrow()); // immutable borrow at runtime

// Rc<RefCell<T>>: shared mutable state (single-threaded)
let shared_vec = Rc::new(RefCell::new(Vec::new()));
let clone = Rc::clone(&shared_vec);
clone.borrow_mut().push(42);

// Arc<T>: atomic reference counting (thread-safe Rc)
// Arc<Mutex<T>>: shared mutable state across threads
let counter = Arc::new(Mutex::new(0));

let handles: Vec<_> = (0..10).map(|_| {
    let counter = Arc::clone(&counter);
    std::thread::spawn(move || {
        let mut num = counter.lock().unwrap();
        *num += 1;
    })
}).collect();

for handle in handles {
    handle.join().unwrap();
}
println!("Result: {}", *counter.lock().unwrap()); // 10

// Cow<T>: clone-on-write for avoiding unnecessary allocations
use std::borrow::Cow;

fn process_name(name: &str) -> Cow<'_, str> {
    if name.contains(' ') {
        Cow::Owned(name.replace(' ', "_"))
    } else {
        Cow::Borrowed(name)
    }
}
```

## Unsafe Rust Guidelines

`unsafe` does not disable all checks; it unlocks five specific capabilities. Minimize its surface area and document all invariants.

```rust
// The five unsafe superpowers:
// 1. Dereference raw pointers
// 2. Call unsafe functions
// 3. Access or modify mutable static variables
// 4. Implement unsafe traits
// 5. Access fields of unions

// Safe abstraction over unsafe code (the recommended pattern)
fn split_at_mut(values: &mut [i32], mid: usize) -> (&mut [i32], &mut [i32]) {
    let len = values.len();
    let ptr = values.as_mut_ptr();

    assert!(mid <= len); // invariant check before unsafe

    unsafe {
        (
            std::slice::from_raw_parts_mut(ptr, mid),
            std::slice::from_raw_parts_mut(ptr.add(mid), len - mid),
        )
    }
}

// FFI (Foreign Function Interface)
extern "C" {
    fn abs(input: i32) -> i32;
}

fn safe_abs(x: i32) -> i32 {
    unsafe { abs(x) }
}

// Guidelines for unsafe code:
// 1. Keep unsafe blocks as small as possible
// 2. Document the safety invariants with // SAFETY: comments
// 3. Use #[deny(unsafe_op_in_unsafe_fn)] to require unsafe blocks inside unsafe fns
// 4. Use tools: Miri (UB detection), cargo-careful, address sanitizer
// 5. Prefer safe abstractions from established crates over writing your own unsafe

// SAFETY comment convention
unsafe fn dangerous_operation(ptr: *const u8, len: usize) -> &'static [u8] {
    // SAFETY: Caller guarantees that ptr is valid for len bytes
    // and the memory will not be modified for 'static lifetime.
    std::slice::from_raw_parts(ptr, len)
}
```
