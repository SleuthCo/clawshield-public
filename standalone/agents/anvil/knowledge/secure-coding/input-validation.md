---
framework: "Input Validation"
version: "1.0"
domain: "Security"
agent: "friday"
tags: ["input-validation", "owasp", "xss", "csrf", "sql-injection", "csp", "output-encoding"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Input Validation and Output Encoding

## OWASP Input Validation Principles

Input validation is the first line of defense against injection attacks. All data from external sources (user input, API calls, file uploads, database reads, environment variables) should be treated as untrusted.

**Validation strategies:**

- **Allow-list (preferred):** Define exactly what is acceptable. Reject everything else. More secure but more restrictive.
- **Deny-list (avoid):** Define what is not acceptable. Allow everything else. Less secure because attackers find bypasses.
- **Syntactic validation:** Verify the format (data type, length, range, pattern). Email must match a regex, age must be 0-150, country code must be in ISO 3166 list.
- **Semantic validation:** Verify the business logic. Start date must be before end date, quantity cannot be negative, user cannot transfer more than their balance.

**Validation location:** Validate on the server side, always. Client-side validation is for user experience only; it is trivially bypassed. Validate at the API boundary (controller/handler layer) before data reaches business logic.

```typescript
import { z } from "zod";

// Schema-based validation with Zod
const CreateUserSchema = z.object({
  name: z.string().min(1).max(100).trim(),
  email: z.string().email().max(254).toLowerCase(),
  age: z.number().int().min(0).max(150).optional(),
  role: z.enum(["user", "admin", "moderator"]),
  bio: z.string().max(1000).optional(),
});

type CreateUserInput = z.infer<typeof CreateUserSchema>;

// In the handler
app.post("/api/users", async (req, res) => {
  const result = CreateUserSchema.safeParse(req.body);
  if (!result.success) {
    return res.status(422).json({
      error: "VALIDATION_ERROR",
      details: result.error.flatten(),
    });
  }
  const validatedInput: CreateUserInput = result.data;
  // Safe to use validatedInput
});
```

**Validation libraries by language:** Zod, Yup, io-ts (TypeScript), Pydantic, marshmallow (Python), validator (Go), serde with custom validators (Rust).

## Parameterized Queries

Parameterized queries (prepared statements) are the primary defense against SQL injection. They separate SQL structure from data, making it impossible for user input to alter the query structure.

```typescript
// GOOD: Parameterized query
const result = await pool.query(
  "SELECT * FROM users WHERE email = $1 AND status = $2",
  [userEmail, "active"]
);

// BAD: String interpolation (SQL injection vulnerability)
const result = await pool.query(
  `SELECT * FROM users WHERE email = '${userEmail}' AND status = 'active'`
);
// If userEmail = "' OR '1'='1" then the query returns all users
```

**ORM safety:** Most ORMs use parameterized queries by default for standard operations (find, save, update). However, raw query methods may still be vulnerable. Always use parameterized versions even in raw queries.

```python
# SQLAlchemy - safe
result = session.execute(
    text("SELECT * FROM users WHERE email = :email"),
    {"email": user_email}
)

# SQLAlchemy - UNSAFE (do not do this)
result = session.execute(
    text(f"SELECT * FROM users WHERE email = '{user_email}'")
)
```

**Dynamic queries:** When building dynamic WHERE clauses, use query builders that support parameterization rather than string concatenation.

```typescript
// Safe dynamic query building
function buildQuery(filters: { name?: string; status?: string; minAge?: number }) {
  const conditions: string[] = [];
  const params: any[] = [];
  let paramIndex = 1;

  if (filters.name) {
    conditions.push(`name ILIKE $${paramIndex++}`);
    params.push(`%${filters.name}%`);
  }
  if (filters.status) {
    conditions.push(`status = $${paramIndex++}`);
    params.push(filters.status);
  }
  if (filters.minAge !== undefined) {
    conditions.push(`age >= $${paramIndex++}`);
    params.push(filters.minAge);
  }

  const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
  return { query: `SELECT * FROM users ${where}`, params };
}
```

## XSS Prevention

Cross-Site Scripting (XSS) occurs when an attacker injects malicious scripts into content served to other users. There are three types.

**Stored XSS:** Malicious script is stored in the database (e.g., in a user bio or comment) and served to other users.

**Reflected XSS:** Malicious script is reflected from the request (e.g., a search query parameter) back in the response.

**DOM-based XSS:** Malicious script is injected through client-side JavaScript that manipulates the DOM using untrusted data.

**Prevention:**

1. **Output encoding:** Encode data before inserting it into HTML, JavaScript, CSS, or URLs. Use context-appropriate encoding.

```typescript
// HTML context: encode < > & " '
function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}

// Most template engines auto-escape by default
// React: JSX auto-escapes by default
// Nunjucks: {{ variable }} auto-escapes; {{ variable | safe }} does not
```

2. **Content Security Policy (CSP):** HTTP header that restricts which sources the browser can load scripts, styles, and other resources from.

3. **Use frameworks that auto-escape:** React, Angular, Vue, and modern template engines auto-escape output by default. Avoid raw HTML insertion (`dangerouslySetInnerHTML`, `v-html`, `[innerHTML]`) unless the content is sanitized.

4. **Sanitize rich text:** If users can submit HTML (rich text editors), use a sanitization library (DOMPurify for browsers, sanitize-html for Node.js) with a strict allow-list of tags and attributes.

## CSRF Tokens

Cross-Site Request Forgery (CSRF) tricks a user's browser into making unwanted requests to a site where the user is authenticated. The browser automatically includes cookies with the request.

**Prevention mechanisms:**

1. **Synchronizer token pattern:** Generate a random token per session, include it in forms and AJAX headers. The server validates the token matches the session.

```html
<form method="POST" action="/transfer">
  <input type="hidden" name="csrf_token" value="random_token_here">
  <input type="text" name="amount">
  <button type="submit">Transfer</button>
</form>
```

2. **SameSite cookies:** Set `SameSite=Lax` (default in modern browsers) or `SameSite=Strict` on session cookies. Lax prevents cross-site POST requests from including the cookie. Strict prevents all cross-site requests from including the cookie.

```
Set-Cookie: session=abc123; SameSite=Lax; Secure; HttpOnly; Path=/
```

3. **Double-submit cookie pattern:** Set a random value in both a cookie and a request header/body. The server verifies they match. This works because an attacker cannot read the cookie value from a different origin.

4. **Custom request headers:** For AJAX requests, require a custom header (e.g., `X-Requested-With: XMLHttpRequest`). Browsers do not add custom headers to cross-origin requests without CORS preflight.

**APIs using bearer tokens (JWTs in Authorization header) are not vulnerable to CSRF** because the token is not automatically included by the browser. CSRF is primarily a concern for cookie-based authentication.

## Content Security Policy

CSP is an HTTP response header that tells the browser which sources of content are trusted. It is the most effective defense against XSS.

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self' https://cdn.example.com;
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https://images.example.com;
  font-src 'self' https://fonts.googleapis.com;
  connect-src 'self' https://api.example.com;
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self';
  upgrade-insecure-requests;
```

**Key directives:**

- `default-src`: Fallback for all resource types.
- `script-src`: Where scripts can be loaded from. Avoid `'unsafe-inline'` and `'unsafe-eval'`. Use nonces or hashes for inline scripts.
- `style-src`: Where stylesheets can be loaded from.
- `connect-src`: Where XHR/fetch can connect to.
- `frame-ancestors`: Which sites can embed this page in an iframe. Replaces `X-Frame-Options`.
- `report-uri` / `report-to`: Where to send violation reports.

**CSP deployment strategy:**

1. Start with `Content-Security-Policy-Report-Only` to collect violations without blocking.
2. Analyze reports to identify legitimate sources.
3. Build the allow-list based on reports.
4. Switch to enforcement mode (`Content-Security-Policy`).
5. Monitor violation reports continuously.

## Output Encoding

Output encoding transforms data so it is treated as data, not as code, in the target context.

**Context-specific encoding:**

- **HTML body:** Encode `< > & " '` as HTML entities.
- **HTML attribute:** Encode all non-alphanumeric characters. Quote attribute values.
- **JavaScript:** Encode non-alphanumeric characters using `\xHH` or `\uHHHH` escape sequences.
- **URL:** Percent-encode special characters using `encodeURIComponent()`.
- **CSS:** Encode non-alphanumeric characters using `\HHHHHH` escape sequences.

**Never mix contexts:** Do not put user data inside `<script>` tags. Do not construct JavaScript strings from server-side variables. If you must, use JSON serialization with proper encoding.

```typescript
// Safe: pass data through a data attribute
const element = document.createElement("div");
element.dataset.userId = userInput; // Auto-encoded by the DOM API
element.textContent = userInput;    // Auto-encoded as text, not HTML

// Unsafe: constructing script content from user data
const html = `<script>var name = "${userInput}";</script>`; // XSS risk
```

## File Upload Security

File uploads are a common attack vector. Malicious files can contain executable code, exploit parsers, or exhaust server resources.

**Validation checklist:**

- **Validate file type:** Check the MIME type from the file header (magic bytes), not just the file extension. Extensions can be spoofed.
- **Restrict allowed types:** Allow-list specific MIME types (e.g., `image/jpeg`, `image/png`, `application/pdf`).
- **Limit file size:** Set a maximum file size at the web server level and in the application. Reject oversized files early.
- **Rename files:** Generate a random filename (UUID) on the server. Never use the user-provided filename for storage.
- **Store outside web root:** Uploaded files should not be directly accessible by URL. Serve them through a controller that checks authorization.
- **Scan for malware:** Use ClamAV or a cloud-based scanning service for uploaded files.
- **Strip metadata:** Remove EXIF data from images (may contain GPS coordinates, device info).

```typescript
const ALLOWED_TYPES = new Set(["image/jpeg", "image/png", "image/webp", "application/pdf"]);
const MAX_SIZE = 10 * 1024 * 1024; // 10 MB

async function handleUpload(file: UploadedFile): Promise<string> {
  if (!ALLOWED_TYPES.has(file.mimetype)) {
    throw new ValidationError("File type not allowed");
  }
  if (file.size > MAX_SIZE) {
    throw new ValidationError("File too large");
  }

  // Verify actual file type from magic bytes
  const actualType = await fileTypeFromBuffer(file.buffer);
  if (!actualType || !ALLOWED_TYPES.has(actualType.mime)) {
    throw new ValidationError("File content does not match declared type");
  }

  const safeFilename = `${crypto.randomUUID()}.${actualType.ext}`;
  await storage.upload(safeFilename, file.buffer);
  return safeFilename;
}
```

## Deserialization Safety

Insecure deserialization can lead to remote code execution, denial of service, or data tampering. Never deserialize untrusted data without validation.

**Dangerous deserialization:**

- **Python:** `pickle.loads()` can execute arbitrary code. Never unpickle data from untrusted sources. Use JSON or MessagePack for data exchange.
- **Java:** `ObjectInputStream.readObject()` is a common RCE vector. Use allow-lists for deserializable classes. Prefer JSON (Jackson/Gson) over Java serialization.
- **PHP:** `unserialize()` with user-controlled data is dangerous. Use `json_decode()` instead.
- **YAML:** `yaml.load()` (Python) can execute arbitrary code with `!!python/object`. Use `yaml.safe_load()` instead.

**Safe alternatives:**

- Use JSON for data exchange. JSON parsers do not execute code during parsing.
- Use Protocol Buffers or Avro for typed serialization with schema validation.
- Use MessagePack for compact binary serialization without code execution risk.
- If you must use language-specific serialization, validate and constrain the types that can be deserialized.
