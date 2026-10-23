# Test Cases

Use only authorized targets.

| No. | Test | Expected result |
|---|---|---|
| 1 | Enter a valid public HTTPS site | Report loads; HTTPS should show PASS if final URL is HTTPS |
| 2 | Enter a valid public HTTP-only site | HTTPS check should show WARNING if it remains on HTTP |
| 3 | Enter a malformed URL | Friendly validation or connection message |
| 4 | Enter `http://127.0.0.1` | Blocked as a non-public target |
| 5 | Enter `http://localhost` | Blocked |
| 6 | Click Download JSON Report after a scan | A JSON report file downloads |
| 7 | Enter a host that does not resolve | Friendly hostname resolution message |

Results vary by website and network. Record the actual observed results in your submission.
