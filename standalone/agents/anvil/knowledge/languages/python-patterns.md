---
framework: "Python"
version: "1.0"
domain: "Programming Languages"
agent: "friday"
tags: ["python", "type-hints", "async", "dataclasses", "protocols", "packaging"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Modern Python Patterns (3.11+)

## Type Hints and Advanced Typing

Python's type system is gradual: type hints are optional annotations checked by tools like mypy, pyright, or pytype, not enforced at runtime by default.

```python
from typing import TypeVar, ParamSpec, Concatenate, TypeAlias, assert_type
from collections.abc import Callable, Sequence, Mapping

# Basic annotations
def greet(name: str, excited: bool = False) -> str:
    return f"Hello, {name}{'!' if excited else '.'}"

# Union types (PEP 604, Python 3.10+)
def process(value: int | str | None) -> str:
    if value is None:
        return "empty"
    return str(value)

# TypeVar with bound
T = TypeVar("T", bound="Comparable")

# ParamSpec for decorator typing (PEP 612)
P = ParamSpec("P")
R = TypeVar("R")

def log_calls(func: Callable[P, R]) -> Callable[P, R]:
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        print(f"Calling {func.__name__}")
        return func(*args, **kwargs)
    return wrapper

# TypeAlias for clarity (PEP 613)
JSON: TypeAlias = dict[str, "JSON"] | list["JSON"] | str | int | float | bool | None

# TypeGuard (PEP 647)
from typing import TypeGuard

def is_str_list(val: list[object]) -> TypeGuard[list[str]]:
    return all(isinstance(x, str) for x in val)

# Self type (PEP 673, Python 3.11+)
from typing import Self

class Builder:
    def set_name(self, name: str) -> Self:
        self.name = name
        return self

# Override decorator (PEP 698, Python 3.12+)
from typing import override

class Base:
    def process(self) -> None: ...

class Child(Base):
    @override
    def process(self) -> None: ...  # mypy errors if Base.process doesn't exist
```

## Dataclasses

Dataclasses eliminate boilerplate for classes that primarily hold data. They auto-generate `__init__`, `__repr__`, `__eq__`, and optionally `__hash__`, `__order__`.

```python
from dataclasses import dataclass, field, asdict, replace
from datetime import datetime

@dataclass(frozen=True, slots=True)
class Money:
    amount: int
    currency: str = "USD"

    def add(self, other: "Money") -> "Money":
        if self.currency != other.currency:
            raise ValueError("Currency mismatch")
        return Money(self.amount + other.amount, self.currency)

# Mutable with defaults and field factories
@dataclass
class Order:
    id: str
    items: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    _total: float = field(init=False, default=0.0)

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("Order ID is required")

# Key flags:
# frozen=True   -> immutable instances (enables hashing)
# slots=True    -> uses __slots__ for memory efficiency (Python 3.10+)
# kw_only=True  -> all fields are keyword-only (Python 3.10+)
# match_args=True -> enables structural pattern matching (default True)

# Inheritance
@dataclass(frozen=True, slots=True)
class PremiumOrder(Order):
    discount: float = 0.0

# Utility functions
order = Order(id="ord_1", items=["widget"])
order_dict = asdict(order)
updated = replace(order, id="ord_2")
```

## Protocols and Structural Subtyping

Protocols (PEP 544) enable structural subtyping: a class matches a Protocol if it has the required attributes and methods, without explicit inheritance.

```python
from typing import Protocol, runtime_checkable

class Renderable(Protocol):
    def render(self) -> str: ...

class HTMLWidget:
    def render(self) -> str:
        return "<div>Widget</div>"

class JSONResponse:
    def render(self) -> str:
        return '{"status": "ok"}'

# Both satisfy Renderable without inheriting from it
def display(item: Renderable) -> None:
    print(item.render())

display(HTMLWidget())    # OK
display(JSONResponse())  # OK

# runtime_checkable enables isinstance checks (limited to method existence)
@runtime_checkable
class Closeable(Protocol):
    def close(self) -> None: ...

import io
assert isinstance(io.StringIO(), Closeable)  # True

# Protocol with properties
class Sized(Protocol):
    @property
    def size(self) -> int: ...

# Protocol with generic
from typing import TypeVar
T_co = TypeVar("T_co", covariant=True)

class Repository(Protocol[T_co]):
    def get(self, id: str) -> T_co | None: ...
    def list_all(self) -> list[T_co]: ...
```

## Async/Await Patterns

Python's `asyncio` provides cooperative multitasking via coroutines. Use async for I/O-bound concurrency, not CPU-bound parallelism.

```python
import asyncio
from collections.abc import AsyncIterator

# Basic async function
async def fetch_user(user_id: str) -> dict:
    await asyncio.sleep(0.1)  # simulate I/O
    return {"id": user_id, "name": "Alice"}

# Concurrent execution with gather
async def fetch_all_users(ids: list[str]) -> list[dict]:
    tasks = [fetch_user(uid) for uid in ids]
    return await asyncio.gather(*tasks)

# TaskGroup (Python 3.11+) -- structured concurrency with proper error handling
async def fetch_with_taskgroup(ids: list[str]) -> list[dict]:
    results: list[dict] = []
    async with asyncio.TaskGroup() as tg:
        for uid in ids:
            tg.create_task(_fetch_and_collect(uid, results))
    return results

async def _fetch_and_collect(uid: str, results: list[dict]) -> None:
    result = await fetch_user(uid)
    results.append(result)

# Async iterator
async def paginate(url: str) -> AsyncIterator[list[dict]]:
    page = 1
    while True:
        data = await fetch_page(url, page)
        if not data:
            break
        yield data
        page += 1

# Async context manager
class AsyncDBConnection:
    async def __aenter__(self) -> "AsyncDBConnection":
        self.conn = await create_connection()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.conn.close()

# Semaphore for rate limiting
async def rate_limited_fetch(urls: list[str], max_concurrent: int = 10) -> list[str]:
    semaphore = asyncio.Semaphore(max_concurrent)

    async def fetch_one(url: str) -> str:
        async with semaphore:
            return await http_get(url)

    return await asyncio.gather(*[fetch_one(u) for u in urls])
```

## Context Managers

Context managers manage resource lifecycle using `__enter__`/`__exit__` or the `contextlib` module.

```python
from contextlib import contextmanager, asynccontextmanager, suppress, ExitStack
from typing import Generator

# Class-based context manager
class Timer:
    def __enter__(self) -> "Timer":
        self.start = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self.elapsed = time.perf_counter() - self.start
        return False  # don't suppress exceptions

# Generator-based (simpler)
@contextmanager
def temporary_directory() -> Generator[str, None, None]:
    path = tempfile.mkdtemp()
    try:
        yield path
    finally:
        shutil.rmtree(path)

# Async context manager
@asynccontextmanager
async def managed_transaction(db):
    tx = await db.begin()
    try:
        yield tx
        await tx.commit()
    except Exception:
        await tx.rollback()
        raise

# ExitStack for dynamic context manager composition
def process_files(paths: list[str]) -> list[str]:
    with ExitStack() as stack:
        files = [stack.enter_context(open(p)) for p in paths]
        return [f.read() for f in files]

# suppress specific exceptions
with suppress(FileNotFoundError):
    os.remove("maybe_exists.tmp")
```

## Decorators

Decorators wrap or modify functions and classes. Use `functools.wraps` to preserve the original function's metadata.

```python
import functools
import time
from typing import TypeVar, ParamSpec, Callable

P = ParamSpec("P")
R = TypeVar("R")

# Typed decorator preserving signature
def retry(max_attempts: int = 3, delay: float = 1.0):
    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            last_exception: Exception | None = None
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    time.sleep(delay * (2 ** attempt))
            raise last_exception  # type: ignore[misc]
        return wrapper
    return decorator

@retry(max_attempts=5, delay=0.5)
def call_api(endpoint: str) -> dict:
    ...

# Class decorator
def singleton(cls):
    instances = {}
    @functools.wraps(cls)
    def get_instance(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]
    return get_instance

# Decorator that works with and without arguments
def cache(func: Callable[P, R] | None = None, *, ttl: int = 300):
    def decorator(f: Callable[P, R]) -> Callable[P, R]:
        @functools.wraps(f)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            return f(*args, **kwargs)  # simplified
        return wrapper

    if func is not None:
        return decorator(func)
    return decorator

@cache           # no parentheses
def func_a(): ...

@cache(ttl=60)   # with arguments
def func_b(): ...
```

## Metaclasses

Metaclasses control class creation. They are rarely needed; prefer `__init_subclass__` or class decorators for most use cases.

```python
# __init_subclass__ (preferred over metaclasses for simple customization)
class Plugin:
    _registry: dict[str, type] = {}

    def __init_subclass__(cls, *, name: str = "", **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        registered_name = name or cls.__name__.lower()
        Plugin._registry[registered_name] = cls

class JSONPlugin(Plugin, name="json"):
    pass

# Metaclass example: enforcing an interface
class InterfaceMeta(type):
    def __new__(mcs, name: str, bases: tuple, namespace: dict):
        cls = super().__new__(mcs, name, bases, namespace)
        if bases:  # skip the base class itself
            required = {"execute", "validate"}
            missing = required - set(namespace)
            if missing:
                raise TypeError(f"{name} must implement: {missing}")
        return cls

class Command(metaclass=InterfaceMeta):
    pass

class CreateUser(Command):
    def execute(self): ...
    def validate(self): ...
    # Missing either method would raise TypeError at class definition time

# Abstract base classes (preferred for interface enforcement)
from abc import ABC, abstractmethod

class Repository(ABC):
    @abstractmethod
    def save(self, entity) -> None: ...

    @abstractmethod
    def find(self, id: str): ...
```

## Packaging with pyproject.toml

PEP 621 standardized project metadata in `pyproject.toml`. This replaces `setup.py`, `setup.cfg`, and `requirements.txt` for project configuration.

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "my-service"
version = "1.2.0"
description = "A microservice for processing orders"
readme = "README.md"
license = "MIT"
requires-python = ">=3.11"
authors = [{ name = "Team", email = "team@example.com" }]

dependencies = [
    "httpx>=0.25",
    "pydantic>=2.0",
    "sqlalchemy>=2.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0",
    "mypy>=1.5",
    "ruff>=0.1",
    "coverage>=7.0",
]

[project.scripts]
my-service = "my_service.cli:main"

[tool.mypy]
strict = true
python_version = "3.11"

[tool.ruff]
target-version = "py311"
select = ["E", "F", "I", "N", "UP", "B", "A", "SIM", "TCH"]

[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"

[tool.coverage.run]
source = ["my_service"]
branch = true
```

Build backends: `hatchling` (Hatch), `flit_core` (Flit), `setuptools` (legacy), `pdm-backend` (PDM), and `maturin` (Rust extensions).

## Pattern Matching (Python 3.10+)

Structural pattern matching provides expressive destructuring and dispatch.

```python
from dataclasses import dataclass

@dataclass
class Point:
    x: float
    y: float

def describe(obj: object) -> str:
    match obj:
        case Point(x=0, y=0):
            return "origin"
        case Point(x, y) if x == y:
            return f"diagonal at {x}"
        case Point(x, y):
            return f"point({x}, {y})"
        case {"action": "click", "position": (x, y)}:
            return f"click at ({x}, {y})"
        case [first, *rest] if rest:
            return f"list starting with {first}, {len(rest)} more"
        case str() as s:
            return f"string: {s}"
        case _:
            return "unknown"

# Guard clauses with `if`
def http_response(status: int) -> str:
    match status:
        case 200:
            return "OK"
        case 301 | 302:
            return "Redirect"
        case code if 400 <= code < 500:
            return "Client error"
        case code if 500 <= code < 600:
            return "Server error"
        case _:
            return "Unknown"
```

## Exception Groups and except* (Python 3.11+)

Exception groups bundle multiple exceptions from concurrent operations. The `except*` syntax handles subgroups selectively.

```python
async def fetch_many():
    async with asyncio.TaskGroup() as tg:
        tg.create_task(might_fail_a())
        tg.create_task(might_fail_b())
    # If tasks raise, TaskGroup wraps them in ExceptionGroup

try:
    await fetch_many()
except* ValueError as eg:
    for exc in eg.exceptions:
        print(f"ValueError: {exc}")
except* TypeError as eg:
    for exc in eg.exceptions:
        print(f"TypeError: {exc}")
```
