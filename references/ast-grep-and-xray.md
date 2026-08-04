# ast-grep & xray MCP servers

The pipeline uses two MCP servers for structural and dataflow analysis. Both
run via `uvx` directly from git, so [`uv`](https://docs.astral.sh/uv/) must be
installed on the host. No manual clone or build is required — `uvx` fetches and
runs them on demand.

## Roles

### ast-grep — pattern & structure

[`ast-grep`](https://github.com/ast-grep/ast-grep-mcp) matches code by its
abstract syntax tree rather than plain text. Use it to:

- Locate candidate vulnerable patterns (e.g. concatenated SQL, `eval`/`exec`
  calls, `subprocess` with `shell=True`, raw template rendering).
- Confirm the syntactic shape of a construct across a language.
- Enumerate call sites, function definitions, and imports structurally.

ast-grep answers "**where does this shape of code appear?**"

### xray — taint, dataflow & reachability

[`xray`](https://github.com/srijanshukla18/xray) performs taint and data-flow
analysis. Use it to:

- Trace tainted data from a source to a sink.
- Build call graphs and assess reachability of a candidate sink from an entry
  point.
- Identify sanitization/validation points that sit on a flow.

xray answers "**can untrusted data actually reach this sink, and how?**"

## Typical loop

1. Recon and analyst use **ast-grep** to find candidate sources and sinks.
2. The analyst uses **xray** to connect them — confirming (or ruling out) a
   reachable source-to-sink path and noting any sanitizers on the way.
3. Confirmed paths become findings with the taint flow from
   `taint-analysis.md`.

## Server definitions

Both servers are declared once, in `config.py` (`mcp_servers()`), and shared by
every phase:

```python
{
    "ast-grep": {
        "command": "uvx",
        "args": ["--from", "git+https://github.com/ast-grep/ast-grep-mcp", "ast-grep-server"],
        "client_session_timeout_seconds": 300,
    },
    "xray": {
        "command": "uvx",
        "args": ["--from", "git+https://github.com/srijanshukla18/xray", "xray-mcp"],
        "client_session_timeout_seconds": 300,
    },
}
```

## Installing `uv`

```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# or with Homebrew
brew install uv
```

Confirm it is on your `PATH` with `uv --version`. The first pipeline run will be
slower while `uvx` fetches the two servers; subsequent runs reuse the cache.
