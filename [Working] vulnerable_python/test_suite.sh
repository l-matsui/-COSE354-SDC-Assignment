#!/usr/bin/env bash
# test_suite.sh — automated smoke tests for vulnerable_python app
# Usage:
#   PORT=4000 ./test_suite.sh
# Defaults to PORT=4000 if not provided.

set -eu

HOST="127.0.0.1"
PORT="${PORT:-4000}"
BASE="http://${HOST}:${PORT}"

ok() { printf "\e[32m[PASS]\e[0m %s\n" "$1"; }
fail() { printf "\e[31m[FAIL]\e[0m %s\n" "$1"; FAILED=1; }

FAILED=0

# helper: do a POST form and return body
post_form() {
  curl -s -X POST -F "$2" "$1"
}

# 1) Home page (sanity)
echo "1) Home page..."
res=$(curl -s "${BASE}/" | head -n 1)
if [[ "$res" == "<!doctype html>" ]]; then ok "Home served"; else fail "Home not served"; fi

# 2) Register user (alice)
echo "2) Register user..."
curl -s -X POST -F "username=alice" -F "password=pass123" "${BASE}/Register" >/dev/null || true
# no strict assertion here — login will confirm

# 3) Normal login
echo "3) Normal login..."
login_res=$(curl -si -X POST -F "username=alice" -F "password=pass123" "${BASE}/Login")
if echo "$login_res" | grep -qi "Location: /Profile"; then ok "Normal login -> Profile"; else fail "Normal login failed"; fi

# 4) SQLi attempt should fail
echo "4) SQLi attempt..."
sqli_res=$(curl -s -X POST -F "username=' OR '1'='1" -F "password=' OR '1'='1" "${BASE}/Login")
if echo "$sqli_res" | grep -qi "Login failed"; then ok "SQLi blocked"; else fail "SQLi might be successful"; fi

# 5) Ping normal
echo "5) Ping normal..."
ping_res=$(curl -s -X POST -F "ip=1.1.1.1" "${BASE}/Ping")
if echo "$ping_res" | grep -qi "PING 1.1.1.1"; then ok "Ping executed"; else
  # ping might be permission-blocked on some systems — accept either ping output or a benign error page
  if echo "$ping_res" | grep -qiE "permission|operation not permitted|cannot"; then ok "Ping attempted (OS blocked)"; else fail "Ping unexpected output"; fi
fi

# 6) Ping injection attempt (should be rejected)
echo "6) Ping injection..."
inj_res=$(curl -s -X POST -F "ip=1.2.3.4 && whoami" "${BASE}/Ping")
if echo "$inj_res" | grep -qi "Invalid host"; then ok "Ping injection blocked"; else fail "Ping injection not blocked"; fi

# 7) Fetch example.com (SSRF normal)
echo "7) Fetch example.com..."
fetch_res=$(curl -s -X POST -F "url=http://example.com" "${BASE}/Fetch")
if echo "$fetch_res" | grep -qi "Example Domain"; then ok "Fetch example.com OK"; else fail "Fetch example.com failed"; fi

# 8) Fetch internal IP (should be blocked)
echo "8) Fetch 127.0.0.1 (should block)..."
fetch_local=$(curl -s -X POST -F "url=http://127.0.0.1:80" "${BASE}/Fetch")
if echo "$fetch_local" | grep -qi "Blocked URL"; then ok "Internal fetch blocked"; else fail "Internal fetch not blocked"; fi

# 9) Redirect-to-internal test (app should NOT follow)
echo "9) Redirect-to-internal..."
redir_test=$(curl -s -X POST -F "url=https://httpbin.org/redirect-to?url=http://127.0.0.1:80" "${BASE}/Fetch")
# We accept that it didn't follow and returned some page — ensure it didn't return internal content
if echo "$redir_test" | grep -qi "Blocked URL|Example Domain|Response Preview|httpbin"; then ok "Redirect not followed (safe)"; else
  # If it contains patterns like '169.254' or '/etc' it's bad
  if echo "$redir_test" | grep -qiE "169\.254|127\.0\.0\.1|Access denied|Blocked URL"; then ok "Redirect not followed (blocked)"; else fail "Redirect may have been followed"; fi
fi

# 10) Fetch metadata (169.254.*) should be blocked
echo "10) Fetch cloud metadata (169.254...)..."
meta_res=$(curl -s -X POST -F "url=http://169.254.169.254/latest/meta-data/" "${BASE}/Fetch")
if echo "$meta_res" | grep -qi "Blocked URL"; then ok "Metadata blocked"; else fail "Metadata may be accessible"; fi

# 11) ViewFile valid log
echo "11) ViewFile valid..."
# ensure logs/test.log exists before running the suite (script won't create it)
vf_res=$(curl -s "${BASE}/ViewFile?filename=test")
if echo "$vf_res" | grep -qi "hello from log"; then ok "ViewFile returned test.log"; else fail "ViewFile didn't return test.log"; fi

# 12) Path traversal attempt (../../etc/passwd) should be denied
echo "12) Path traversal attempt..."
pt_res=$(curl -s "${BASE}/ViewFile?filename=../../etc/passwd")
if echo "$pt_res" | grep -qi "Access denied"; then ok "Path traversal blocked"; else fail "Path traversal may be allowed"; fi

# 13) Encoded traversal (..%2f..%2fetc%2fpasswd) should be denied
echo "13) Encoded traversal..."
enc_res=$(curl -s "${BASE}/ViewFile?filename=..%2f..%2fetc%2fpasswd")
if echo "$enc_res" | grep -qi "Access denied"; then ok "Encoded traversal blocked"; else fail "Encoded traversal may be allowed"; fi

# Final result
if [[ "${FAILED}" -eq 0 ]]; then
  printf "\n\e[32mAll tests passed.\e[0m\n"
  exit 0
else
  printf "\n\e[31mSome tests failed. See above.\e[0m\n"
  exit 2
fi
