# CSAagent

CSAagent is a C/C++ defect scanning pipeline:

1. Run Clang Static Analyzer.
2. Build code context.
3. Use an LLM agent to classify findings.
4. Generate reports (`json`, `html`, `csv`).

This repository now supports being used directly as a GitHub Action.

## Run Locally

```bash
python main.py /path/to/src \
  --config config.yaml \
  --compile-commands /path/to/compile_commands.json \
  --output-format json html
```

Useful CI flags:

- `--output-dir data/reports`
- `--summary-json data/reports/csa_summary.json`
- `--fail-on any_issue`
- `--fail-confidence 0.7`

## Use As GitHub Action

In a target repository workflow:

```yaml
name: csaagent-scan

on:
  pull_request:
  push:

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build compile_commands.json (example with CMake)
        run: |
          cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

      - name: Run CSAagent
        id: csa
        uses: maincourses/CSAagent@main
        with:
          src-dir: .
          compile-commands: build/compile_commands.json
          api-key: ${{ secrets.CSA_LLM_API_KEY }}
          output-format: "json html"
          fail-on: "never"
```

## Action Inputs

- `src-dir`: source directory to scan, default `.`
- `config`: config path; empty uses `configs/config.ci.yaml`
- `compile-commands`: optional compile database path
- `output-dir`: report directory, default `data/reports`
- `output-format`: e.g. `json html`
- `fail-on`: `never|true_positive|uncertain|analyzer_failure|true_positive_or_uncertain|any_issue`
- `fail-confidence`: confidence threshold used by fail policy
- `api-key`: API key exposed as `API_KEY` for config

## Action Outputs

- `json-report`: latest JSON report path
- `html-report`: latest HTML report path
- `summary-json`: machine-readable summary path
