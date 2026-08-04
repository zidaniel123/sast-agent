# Taint flow & Proof-of-Concept formatting spec

Shared reference for the **analyst** and **reporter** skills. Both phases must
present taint flows and code evidence the same way, so the specification lives
here once.

## Taint flow structure

Every finding traces untrusted data with three labeled stages:

- **Source** — where untrusted/attacker-controlled data enters (request
  parameter, CLI arg, deserialized payload, file, environment).
- **Path** — the numbered hops the data takes through the application, including
  any sanitization or validation it does or does not pass.
- **Sink** — where the tainted data causes the security impact (query
  execution, command execution, file path, template, response).

## Snippet quality rules

- **Use markdown code blocks** with a language tag for every snippet in the
  taint flow (```` ```java ````, ```` ```python ````, ```` ```javascript ````,
  etc.). Never use inline code for taint-flow steps.
- **Show context**: each snippet is at least three lines — one line above, the
  focus line, and one line below.
- **Number the hops** (`1.`, `2.`, `3.`) through the Path.
- **Bold** the key variables, functions, and security concerns.
- Use **relative** file paths from the project root (e.g. `app/auth.py:45`),
  never absolute paths.
- Include line numbers and file paths for all evidence.
- Keep explanations concise and professional.

## Proof of Concept

- Include a PoC code snippet in the taint flow whenever one can be constructed.
- PoC code is raw and comment-free — clean, executable examples.
- The PoC must be relevant to this codebase and vulnerability and be plausibly
  working for the traced path, not a generic placeholder.

## Example

**Source**: User input via request parameter

```java
String userInput = request.getParameter("username");
```

1. **userInput** flows to a sanitization function

```java
public String sanitizeInput(String input) {
    if (input.length() > 50) return input.substring(0, 50);
    return input;
}
```

2. **sanitizedValue** is used in query construction

```java
private String buildQuery(String value) {
    return "SELECT * FROM users WHERE name = '" + value + "'";
}
```

**Sink**: Database query execution

```java
ResultSet rs = statement.executeQuery(buildQuery(sanitizedValue));
```

The length-only check never neutralizes SQL metacharacters, so the tainted
**value** reaches the query string unescaped.
