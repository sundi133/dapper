// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Embedded semgrep ruleset for Dapper's deterministic white-box pass.
 *
 * Shipped as a string constant (not a .yaml file) so it is compiled into the
 * JS bundle and needs no build-time asset copy. At runtime it is written to a
 * temp file and passed to `semgrep --config <file>`.
 *
 * Rules are intentionally conservative and standard-syntax. If semgrep rejects
 * the config for any reason, the runner degrades gracefully (yields nothing) —
 * an ineffective ruleset can never break the pipeline.
 *
 * `metadata.source-kind: http-input` on taint sources drives the reachability
 * signal (capability 1.3): a sink fed by untrusted HTTP input is internet-reachable.
 * `metadata.category: authz` marks route-surface rules (capability 1.4).
 */
export const SEMGREP_RULESET_YAML = `rules:
  # ---------------- Taint / dataflow (capability 1.2 + 1.3) ----------------
  - id: dapper-taint-sqli-js
    mode: taint
    languages: [javascript, typescript]
    severity: ERROR
    message: "Untrusted HTTP input flows into a SQL query (possible SQL injection)."
    metadata:
      category: sqli
      cwe: ["CWE-89"]
      owasp: ["A03:2021 - Injection"]
      source-kind: http-input
    pattern-sources:
      - pattern-either:
          - pattern: $REQ.body
          - pattern: $REQ.query
          - pattern: $REQ.params
          - pattern: $REQ.headers
          - pattern: $REQ.cookies
    pattern-sinks:
      - pattern-either:
          - pattern: $DB.query(...)
          - pattern: $DB.raw(...)
          - pattern: $CONN.execute(...)
          - pattern: $SEQ.query(...)

  - id: dapper-taint-command-injection-js
    mode: taint
    languages: [javascript, typescript]
    severity: ERROR
    message: "Untrusted HTTP input flows into an OS command (possible command injection)."
    metadata:
      category: command-injection
      cwe: ["CWE-78"]
      owasp: ["A03:2021 - Injection"]
      source-kind: http-input
    pattern-sources:
      - pattern-either:
          - pattern: $REQ.body
          - pattern: $REQ.query
          - pattern: $REQ.params
          - pattern: $REQ.headers
    pattern-sinks:
      - pattern-either:
          - pattern: child_process.exec(...)
          - pattern: child_process.execSync(...)
          - pattern: child_process.spawn(...)
          - pattern: exec(...)
          - pattern: execSync(...)

  - id: dapper-taint-path-traversal-js
    mode: taint
    languages: [javascript, typescript]
    severity: ERROR
    message: "Untrusted HTTP input flows into a filesystem path (possible path traversal / LFI)."
    metadata:
      category: path-traversal
      cwe: ["CWE-22"]
      owasp: ["A01:2021 - Broken Access Control"]
      source-kind: http-input
    pattern-sources:
      - pattern-either:
          - pattern: $REQ.body
          - pattern: $REQ.query
          - pattern: $REQ.params
    pattern-sinks:
      - pattern-either:
          - pattern: fs.readFile(...)
          - pattern: fs.readFileSync(...)
          - pattern: fs.createReadStream(...)
          - pattern: fs.sendFile(...)
          - pattern: $RES.sendFile(...)

  - id: dapper-taint-ssrf-js
    mode: taint
    languages: [javascript, typescript]
    severity: ERROR
    message: "Untrusted HTTP input flows into a server-side request (possible SSRF)."
    metadata:
      category: ssrf
      cwe: ["CWE-918"]
      owasp: ["A10:2021 - Server-Side Request Forgery"]
      source-kind: http-input
    pattern-sources:
      - pattern-either:
          - pattern: $REQ.body
          - pattern: $REQ.query
          - pattern: $REQ.params
    pattern-sinks:
      - pattern-either:
          - pattern: axios.get(...)
          - pattern: axios.post(...)
          - pattern: axios(...)
          - pattern: fetch(...)
          - pattern: http.get(...)
          - pattern: https.get(...)
          - pattern: request(...)

  - id: dapper-taint-sqli-python
    mode: taint
    languages: [python]
    severity: ERROR
    message: "Untrusted HTTP input flows into a SQL query (possible SQL injection)."
    metadata:
      category: sqli
      cwe: ["CWE-89"]
      owasp: ["A03:2021 - Injection"]
      source-kind: http-input
    pattern-sources:
      - pattern-either:
          - pattern: request.args
          - pattern: request.form
          - pattern: request.values
          - pattern: request.get_json(...)
          - pattern: request.data
    pattern-sinks:
      - pattern-either:
          - pattern: $CUR.execute(...)
          - pattern: $DB.execute(...)
          - pattern: $DB.raw(...)

  - id: dapper-taint-command-injection-python
    mode: taint
    languages: [python]
    severity: ERROR
    message: "Untrusted HTTP input flows into an OS command (possible command injection)."
    metadata:
      category: command-injection
      cwe: ["CWE-78"]
      owasp: ["A03:2021 - Injection"]
      source-kind: http-input
    pattern-sources:
      - pattern-either:
          - pattern: request.args
          - pattern: request.form
          - pattern: request.values
    pattern-sinks:
      - pattern-either:
          - pattern: os.system(...)
          - pattern: os.popen(...)
          - pattern: subprocess.call(...)
          - pattern: subprocess.run(...)
          - pattern: subprocess.Popen(...)

  # ---------------- Dangerous sinks / SAST (capability 1.1) ----------------
  - id: dapper-sink-eval-js
    languages: [javascript, typescript]
    severity: WARNING
    message: "Use of eval() on dynamic input can lead to code injection."
    metadata:
      category: code-injection
      cwe: ["CWE-95"]
      owasp: ["A03:2021 - Injection"]
    patterns:
      - pattern: eval(...)

  - id: dapper-sink-weak-hash-js
    languages: [javascript, typescript]
    severity: WARNING
    message: "Weak hashing algorithm (MD5/SHA1) used; prefer SHA-256+ / bcrypt / argon2."
    metadata:
      category: crypto
      cwe: ["CWE-327"]
      owasp: ["A02:2021 - Cryptographic Failures"]
    patterns:
      - pattern-either:
          - pattern: crypto.createHash("md5")
          - pattern: crypto.createHash("sha1")

  - id: dapper-sink-weak-hash-python
    languages: [python]
    severity: WARNING
    message: "Weak hashing algorithm (MD5/SHA1) used; prefer SHA-256+ / bcrypt / argon2."
    metadata:
      category: crypto
      cwe: ["CWE-327"]
      owasp: ["A02:2021 - Cryptographic Failures"]
    patterns:
      - pattern-either:
          - pattern: hashlib.md5(...)
          - pattern: hashlib.sha1(...)

  - id: dapper-sink-dangerous-yaml-python
    languages: [python]
    severity: WARNING
    message: "yaml.load without SafeLoader can deserialize arbitrary objects."
    metadata:
      category: deserialization
      cwe: ["CWE-502"]
      owasp: ["A08:2021 - Software and Data Integrity Failures"]
    patterns:
      - pattern: yaml.load($X)

  # ---------------- Authorization surface (capability 1.4) ----------------
  # Enumerates internet-facing route handlers so authorization can be verified.
  # Heuristic (surface map), not a proof of missing auth.
  - id: dapper-authz-express-route
    languages: [javascript, typescript]
    severity: INFO
    message: "HTTP route handler — verify authentication / ownership / role checks are enforced."
    metadata:
      category: authz
      cwe: ["CWE-862"]
      owasp: ["A01:2021 - Broken Access Control"]
    patterns:
      - pattern-either:
          - pattern: $APP.get($ROUTE, ...)
          - pattern: $APP.post($ROUTE, ...)
          - pattern: $APP.put($ROUTE, ...)
          - pattern: $APP.delete($ROUTE, ...)
          - pattern: $APP.patch($ROUTE, ...)

  - id: dapper-authz-flask-route
    languages: [python]
    severity: INFO
    message: "HTTP route handler — verify authentication / ownership / role checks are enforced."
    metadata:
      category: authz
      cwe: ["CWE-862"]
      owasp: ["A01:2021 - Broken Access Control"]
    patterns:
      - pattern: "@$APP.route(...)"
`;
