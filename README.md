# SAST Agent

An autonomous static application security testing (SAST) agent that reviews a
codebase you have access to and emits a structured JSON findings report. Built
on the [Claude Agent SDK](https://github.com/anthropics/claude-agent-sdk-python).

![SAST agent architecture](docs/architecture.png)

## How it works

The pipeline runs three specialist agents in sequence over a local codebase:

1. **recon** — maps the attack surface: tech stack, auth, user-input entry
   points, and sensitive operations.
2. **analyst** — performs deep vulnerability identification and taint/dataflow
   analysis, tracing untrusted data from source to sink.
3. **reporter** — normalizes the analyst's findings into a validated JSON
   report with severity, CWE, taint analysis, and code evidence.

Two MCP servers do the heavy lifting for the recon and analyst phases:

- **[ast-grep](https://github.com/ast-grep/ast-grep-mcp)** — structural, AST-
  based pattern matching ("where does this shape of code appear?").
- **[xray](https://github.com/srijanshukla18/xray)** — taint, dataflow, and
  reachability analysis ("can untrusted data actually reach this sink?").

See [`references/ast-grep-and-xray.md`](references/ast-grep-and-xray.md) for
details.

## Requirements

- **Python ≥ 3.11**
- **[`uv`](https://docs.astral.sh/uv/)** — the ast-grep and xray MCP servers run
  via `uvx` from git, so `uv` must be on your `PATH`.
- **An LLM gateway and API key** — any Requesty-compatible (OpenAI-style)
  gateway works.

## Install

```bash
pip install -r requirements.txt
```

Install `uv` if you do not have it:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh   # or: brew install uv
```

## Configure

```bash
cp .env.example .env
# then edit .env and fill in your key, base URL, and model
```

The key is read from `REQUESTY_API_KEY`, `OPENAI_API_KEY`, or
`ANTHROPIC_API_KEY` (in that order). The gateway base URL comes from
`OPENAI_API_BASE`, `BASE_URL`, or `ANTHROPIC_BASE_URL`. The model id
(`ANTHROPIC_MODEL`) is gateway-specific — set it to whatever your gateway
exposes.

## Usage

```bash
python main.py --path /path/to/your/codebase
```

Options:

| Flag           | Default     | Description                                  |
| -------------- | ----------- | -------------------------------------------- |
| `--path`       | *(required)*| Directory of the codebase to analyze.        |
| `--output-dir` | `outputs/`  | Where the JSON report is written.            |
| `--model`      | env / default | Override the LLM model id for this run.     |
| `--run-id`     | random UUID | Custom run id (also the report filename).    |

At the end you get a short human summary; the full report is written to
`<output-dir>/<run-id>.json`.

## Output

The reporter emits a single JSON object: `report_metadata` plus a `findings[]`
array. Each finding carries a `vulnerability`, `description`, `cwe_id`,
`severity`, `confidence`, a `taint_analysis` object, and `evidences[]` with code
snippets and a source-to-sink taint flow.

```json
{
  "report_metadata": {
    "codebase_path": "/path/to/your/codebase",
    "report_timestamp": "2026-08-03T12:00:00+00:00",
    "analysis_source": "security_analyst_agent",
    "report_generator": "final_reporter_agent"
  },
  "findings": [
    {
      "vulnerability": "SQL Injection in user lookup",
      "description": "User-controlled 'username' reaches a query built by string concatenation.",
      "cwe_id": "CWE-89",
      "severity": "high",
      "confidence": "high",
      "taint_analysis": {
        "source_location": "app/api/users.py:31",
        "sink_location": "app/db/queries.py:58",
        "data_flow_path": "request param -> length-only sanitizer -> query string",
        "sanitization_present": false,
        "exploitability": "high",
        "impact": "Read/modify arbitrary rows in the users table."
      },
      "evidences": [
        {
          "path": "app/db/queries.py",
          "code_file": "app/db/queries.py",
          "snippet": "return \"SELECT * FROM users WHERE name = '\" + value + \"'\"",
          "taint_flow": "**Source**: ... **Sink**: ...",
          "line_range": "56-58"
        }
      ]
    }
  ]
}
```

## How to customize

The agents' behavior lives in editable Markdown, not Python:

- **`skills/recon/SKILL.md`**, **`skills/analyst/SKILL.md`**,
  **`skills/reporter/SKILL.md`** — each phase's system prompt, with YAML
  frontmatter and a clean body. Placeholders like `{{code_path}}` are filled in
  at runtime.
- **`references/`** — shared specs the skills point to:
  [`taint-analysis.md`](references/taint-analysis.md) (taint-flow + PoC
  formatting), [`severity-and-cwe.md`](references/severity-and-cwe.md) (severity
  rubric + CWE guidance), and
  [`ast-grep-and-xray.md`](references/ast-grep-and-xray.md) (tool usage).

Edit these files to tune scope, house style, or the report schema without
changing code. The loader (`skills.py`) reads them at runtime with a path-escape
guard. The MCP servers and per-phase turn budgets live in `config.py`.

## Safety & authorization

Run this tool **only on code you own or are explicitly authorized to review.**
It performs static analysis — reading and reasoning about source — and never
exploits or interacts with a running system. See [`SECURITY.md`](SECURITY.md).

## Limitations

- Findings are LLM-generated and **require human validation**. Expect false
  positives and occasionally missed issues.
- Severity and confidence are judgment calls; review them against your own
  threat model.
- Analysis quality depends on the model, the codebase size, and the per-phase
  turn budgets.

## License

MIT — see [`LICENSE`](LICENSE).
