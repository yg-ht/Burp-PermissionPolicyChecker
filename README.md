# Burp Permission Policy Checker

Burp Permission Policy Checker is a Burp Suite extension that passively audits
`Permissions-Policy`, `Permissions-Policy-Report-Only`, legacy `Feature-Policy`,
and risky iframe `allow` usage.

The extension is implemented as a single legacy Python/Jython script and
registers both a passive scanner check and a Burp UI tab named
`Permissions Policy Auditor`.

## Features

- Flags missing enforcing `Permissions-Policy` headers on document-like responses.
- Detects deprecated `Feature-Policy` headers.
- Reports `Permissions-Policy-Report-Only` without a matching enforcing policy.
- Finds malformed directives, legacy syntax, invalid allowlists, duplicate directives, and unknown directive names.
- Highlights wildcard allowances for sensitive browser features.
- Highlights explicit cross-origin allowances for high-risk features.
- Checks for configured sensitive features that are not explicitly denied with `()`.
- Reports `report-to` usage when no `Reporting-Endpoints` header is present.
- Finds cross-origin iframes that allow high-risk browser features.

## Requirements

- Burp Suite with the legacy Extender API.
- Jython 2.7 configured as Burp's Python environment.
- `PermissionPolicyChecker.py` from this repository.

## Installation

1. Open Burp Suite.
2. Configure Jython under Burp's Python extension settings if it is not already configured.
3. Add a new extension:
   - Extension type: `Python`
   - Extension file: `PermissionPolicyChecker.py`
4. Confirm the extension loads as `Permissions Policy Auditor`.
5. Open the `Permissions Policy Auditor` tab to tune checks.

## Usage

Add the target application to Burp scope, browse or crawl the application, and
review passive scanner issues in Burp. By default, the extension only analyses
in-scope, document-like responses with status codes in the 2xx range or `304`.

Example strict policy for applications that do not need privileged browser APIs:

```http
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
```

Example restricted delegation:

```http
Permissions-Policy: fullscreen=(self "https://player.example"), geolocation=()
```

## Configuration

The Burp tab exposes checkboxes for each finding category:

- Only analyse in-scope resources.
- Only analyse document-like HTML responses.
- Flag missing policies, deprecated headers, report-only-only policies, syntax errors, unknown directives, duplicate directives, wildcard allowances, cross-origin allowances, sensitive features not denied, and risky iframe `allow` attributes.

The `Directives expected to be explicitly denied with ()` field is a
comma-separated baseline used by the sensitive-feature check. Tune it for
applications that legitimately need features such as passkeys, payments,
geolocation, video, screen sharing, or device access.

`Debug level (0-3)` controls extension output in Burp's extension console:

- `0`: errors only
- `1`: load/unload messages
- `2`: stored findings and duplicate suppression
- `3`: verbose skip/no-issue diagnostics

## Findings

The extension may create the following Burp scanner issues:

- `Permissions-Policy header missing`
- `Deprecated Feature-Policy header present`
- `Permissions-Policy configured in report-only mode only`
- `Permissions-Policy syntax error`
- `Permissions-Policy duplicate directive`
- `Permissions-Policy unknown directive`
- `Permissions-Policy invalid allowlist`
- `Permissions-Policy wildcard allowance for sensitive feature`
- `Permissions-Policy cross-origin allowance for high-risk feature`
- `Permissions-Policy report-to endpoint missing`
- `Permissions-Policy sensitive features not denied`
- `Cross-origin iframe allows high-risk browser feature`

Severities are intentionally conservative. Missing hardening and most
misconfigurations are reported as `Low`, unknown directives and reporting gaps
as `Information`, and enforcing wildcard allowances for sensitive features as
`Medium`.

## How It Works

For each eligible response, the extension parses relevant response headers,
extracts the response body, checks iframe tags with regex-based attribute
matching, builds scanner issue records, and deduplicates repeated findings by
issue name and detail.

The parser expects modern `Permissions-Policy` syntax:

```http
feature=()
feature=*
feature=(self "https://example.com")
```

Legacy values such as `'none'`, `'self'`, semicolon-separated `Feature-Policy`
directives, and unparenthesised allowlists are treated as suspicious in
`Permissions-Policy` headers.

## Limitations

- This is a passive scanner extension; it does not perform active probing.
- HTML iframe detection is regex-based and is intended for practical auditing, not full HTML parsing.
- The known directive list is embedded in the script and should be updated as browser support changes.
- `python3 -m py_compile PermissionPolicyChecker.py` can catch syntax errors, but it does not validate Burp, Swing, or Jython runtime behavior.

## Development

Keep changes compatible with Jython 2.7 and Burp's legacy Extender APIs. Avoid
Python 3-only syntax such as f-strings, type annotations, and dataclasses.

Before submitting changes:

```bash
python3 -m py_compile PermissionPolicyChecker.py
git status --short
```

Then manually load the extension in Burp and validate representative responses
for missing headers, malformed policies, wildcard allowances, cross-origin
allowances, strict baseline results, and iframe `allow` findings.
