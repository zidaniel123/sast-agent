# Security Policy

## Authorized use

This tool performs **static** analysis of source code. Run it only against code
you own or are explicitly authorized to review. It reads and reasons about
code; it does not exploit, attack, or interact with any running system.

## Human review required

Findings are produced by a large language model and **must be validated by a
human** before they are acted on, escalated, or shared. Expect false positives,
occasional missed issues, and severity that needs adjustment. Treat the JSON
report as an investigative lead, not a verdict.

## Reporting a vulnerability in this project

If you find a security issue in this repository itself, please open a private
report to the maintainers (e.g. via GitHub's private security advisory feature)
rather than a public issue. Include reproduction steps and affected versions.
We will acknowledge the report and follow up with a remediation timeline.

## Handling analysis output

Reports can contain sensitive snippets from the analyzed codebase. Store and
share them with the same care as the source they describe.
