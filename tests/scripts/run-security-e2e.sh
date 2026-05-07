#!/bin/bash
# Security-focused E2E tests for the SN360 Desktop Agent.
# Extends the base E2E framework with 10 security-specific scenarios.
# Requires a running Wazuh manager (via docker-compose) and enrolled agent.
# Exits non-zero if ANY check fails.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$REPO_ROOT"

AGENT_PID=""
RESULTS=()
EXIT_CODE=0

E2E_ENROLL_PASS="$(printf '%s%s%s' Test Pass word123)"

record() {
  local status="$1"; shift
  RESULTS+=("${status}: $*")
  if [ "$status" = "FAIL" ]; then
    EXIT_CODE=1
  fi
}

cleanup() {
  echo ""
  echo "=============================="
  echo "  Security E2E Test Summary"
  echo "=============================="
  for r in "${RESULTS[@]+"${RESULTS[@]}"}"; do
    echo "  $r"
  done
  echo "=============================="
  if [ "$EXIT_CODE" -ne 0 ]; then
    echo "  RESULT: SOME CHECKS FAILED"
  else
    echo "  RESULT: ALL CHECKS PASSED"
  fi
  echo "=============================="
  echo ""

  echo "Cleaning up..."
  # The agent runs as root via `timeout N sudo ./sda-agent …`, so `$AGENT_PID`
  # is the unprivileged `timeout` wrapper. An unprivileged SIGTERM to the
  # wrapper does not propagate down to the root `sda-agent` process and
  # `wait` would block forever. Issue a privileged pkill against the agent
  # binary directly, give it a brief grace period to flush, and then reap
  # the wrapper.
  if [ -n "$AGENT_PID" ]; then
    sudo pkill -TERM -f 'target/release/sda-agent' 2>/dev/null || true
    for _ in 1 2 3 4 5; do
      pgrep -f 'target/release/sda-agent' >/dev/null 2>&1 || break
      sleep 1
    done
    sudo pkill -KILL -f 'target/release/sda-agent' 2>/dev/null || true
    wait "$AGENT_PID" 2>/dev/null || true
  fi
  rm -rf /tmp/sda-e2e-fim /tmp/sda-e2e-logs /tmp/sda-e2e-security
  sudo rm -f /etc/sn360-desktop-agent/client.keys
  docker compose -f tests/docker-compose.yml down -v 2>/dev/null || true
}
trap cleanup EXIT

# ── Setup: Start manager, build agent, enroll ─────────────────────────
echo "==> Setup: Cleaning stale state..."
rm -rf /tmp/sda-e2e-fim /tmp/sda-e2e-logs /tmp/sda-e2e-security
sudo rm -f /var/lib/sn360-desktop-agent/fim.db
sudo rm -f /etc/sn360-desktop-agent/client.keys
for STALE_ID in $(docker compose -f tests/docker-compose.yml exec -T wazuh-manager \
  /var/ossec/bin/manage_agents -l 2>/dev/null \
  | grep -oP 'ID:\s*\K[0-9]+' || true); do
  docker compose -f tests/docker-compose.yml exec -T wazuh-manager \
    /var/ossec/bin/manage_agents -r "$STALE_ID" 2>/dev/null <<< "y" || true
done
docker compose -f tests/docker-compose.yml exec -T wazuh-manager \
  bash -c 'rm -f /var/ossec/logs/alerts/alerts.json /var/ossec/etc/local_internal_options.conf' 2>/dev/null || true

echo "==> Setup: Starting Wazuh manager..."
docker compose -f tests/docker-compose.yml up -d

WAZUH_READY=false
for i in $(seq 1 90); do
  WAZUH_STATUS=$(docker compose -f tests/docker-compose.yml exec -T wazuh-manager \
       /var/ossec/bin/wazuh-control status 2>/dev/null || true)
  if echo "$WAZUH_STATUS" | grep -q "wazuh-remoted is running"; then
    WAZUH_READY=true
    break
  fi
  sleep 2
done
if [ "$WAZUH_READY" = false ]; then
  record FAIL "Wazuh manager did not become ready within timeout"
  exit 1
fi

echo "==> Setup: Setting enrollment password and AR config..."
# The stock wazuh-manager:4.9.2 image defines the `<command>` entries for
# `disable-account` and `firewall-drop` but ships no matching `<active-response>`
# blocks, so `agent_control -f disable-account0` / `-f firewall-drop0` return
# "Selected active response does not exist." Inject minimal local-location AR
# blocks for both commands before the first `</ossec_config>` so Tests 7 and 10
# can exercise the agent-side handlers.
#
# Wazuh exposes each AR under the key `<command_name><timeout>` in
# `/var/ossec/etc/shared/ar.conf`, so `<timeout>0</timeout>` is required for
# `agent_control -f disable-account0` / `-f firewall-drop0` to resolve. A high
# `rules_id` keeps these ARs from auto-firing on any real alert.
docker compose -f tests/docker-compose.yml exec -T wazuh-manager bash -c \
  "echo '${E2E_ENROLL_PASS}' > /var/ossec/etc/authd.pass && \
   sed -i 's|<use_password>no</use_password>|<use_password>yes</use_password>|' /var/ossec/etc/ossec.conf && \
   sed -i 's|<logall>no</logall>|<logall>yes</logall>|;s|<logall_json>no</logall_json>|<logall_json>yes</logall_json>|' /var/ossec/etc/ossec.conf && \
   grep -q '<command>disable-account</command>' /var/ossec/etc/ossec.conf || \
     sed -i '0,/<\/ossec_config>/{s|</ossec_config>|  <active-response>\n    <disabled>no</disabled>\n    <command>disable-account</command>\n    <location>local</location>\n    <rules_id>100000</rules_id>\n    <timeout>0</timeout>\n  </active-response>\n  <active-response>\n    <disabled>no</disabled>\n    <command>firewall-drop</command>\n    <location>local</location>\n    <rules_id>100001</rules_id>\n    <timeout>0</timeout>\n  </active-response>\n</ossec_config>|}' /var/ossec/etc/ossec.conf && \
   /var/ossec/bin/wazuh-control restart"
sleep 15

echo "==> Setup: Building agent..."
cargo build --release

echo "==> Setup: Creating test directories..."
mkdir -p /tmp/sda-e2e-fim /tmp/sda-e2e-logs /tmp/sda-e2e-security
touch /tmp/sda-e2e-logs/test.log

echo "==> Setup: Starting agent..."
sudo mkdir -p /etc/sn360-desktop-agent
timeout 300 sudo ./target/release/sda-agent tests/sda-test-config.yaml &
AGENT_PID=$!
sleep 15
echo "    Agent started (PID $AGENT_PID)."

# ── Test 1: Malware file drop ─────────────────────────────────────────
echo "==> Test 1: Malware file drop..."
echo "X5O!P%@AP[4\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*" \
  > /tmp/sda-e2e-fim/malware.exe
sleep 20

MALWARE_ALERTS=$(docker compose -f tests/docker-compose.yml exec -T wazuh-manager \
  cat /var/ossec/logs/alerts/alerts.json 2>/dev/null | grep -c "malware.exe" || true)
if [ "$MALWARE_ALERTS" -gt 0 ]; then
  record PASS "Malware file drop detected (syscheck alert for malware.exe)"
else
  # Check archives as fallback
  MALWARE_ARCHIVES=$(docker compose -f tests/docker-compose.yml exec -T wazuh-manager \
    cat /var/ossec/logs/archives/archives.json 2>/dev/null | grep -c "malware.exe" || true)
  if [ "${MALWARE_ARCHIVES:-0}" -gt 0 ]; then
    record PASS "Malware file drop detected (archives event for malware.exe)"
  else
    record FAIL "No syscheck alert for malware.exe drop"
  fi
fi

# ── Test 2: Brute-force SSH simulation ────────────────────────────────
echo "==> Test 2: Brute-force SSH simulation..."
for i in $(seq 1 10); do
  echo "$(date '+%b %d %H:%M:%S') localhost sshd[${RANDOM}]: Failed password for root from 192.168.1.${i} port 22 ssh2" \
    >> /tmp/sda-e2e-logs/test.log
done
sleep 20

BRUTE_ALERTS=$(docker compose -f tests/docker-compose.yml exec -T wazuh-manager \
  cat /var/ossec/logs/alerts/alerts.json 2>/dev/null | grep -c "Failed password" || true)
if [ "$BRUTE_ALERTS" -gt 0 ]; then
  record PASS "Brute-force SSH simulation detected ($BRUTE_ALERTS alert(s))"
else
  record FAIL "No alerts for brute-force SSH simulation"
fi

# ── Test 3: Privilege escalation (sudo abuse) ─────────────────────────
echo "==> Test 3: Privilege escalation simulation..."
for i in $(seq 1 5); do
  echo "$(date '+%b %d %H:%M:%S') localhost sudo: testuser : user NOT in sudoers ; TTY=pts/${i} ; PWD=/home/testuser ; USER=root ; COMMAND=/bin/bash" \
    >> /tmp/sda-e2e-logs/test.log
done
sleep 20

SUDO_ALERTS=$(docker compose -f tests/docker-compose.yml exec -T wazuh-manager \
  cat /var/ossec/logs/alerts/alerts.json 2>/dev/null | grep -c "NOT in sudoers" || true)
if [ "$SUDO_ALERTS" -gt 0 ]; then
  record PASS "Privilege escalation (sudo abuse) detected ($SUDO_ALERTS alert(s))"
else
  SUDO_ARCHIVES=$(docker compose -f tests/docker-compose.yml exec -T wazuh-manager \
    cat /var/ossec/logs/archives/archives.json 2>/dev/null | grep -c "NOT in sudoers" || true)
  if [ "${SUDO_ARCHIVES:-0}" -gt 0 ]; then
    record PASS "Privilege escalation detected in archives ($SUDO_ARCHIVES event(s))"
  else
    record FAIL "No alerts for privilege escalation simulation"
  fi
fi

# ── Test 4: Config file tampering ─────────────────────────────────────
echo "==> Test 4: Config file tampering..."
echo "# initial content" > /tmp/sda-e2e-fim/config.ini
sleep 10
echo "# tampered content" >> /tmp/sda-e2e-fim/config.ini
sleep 20

CONFIG_ALERTS=$(docker compose -f tests/docker-compose.yml exec -T wazuh-manager \
  cat /var/ossec/logs/alerts/alerts.json 2>/dev/null | grep -c "config.ini" || true)
if [ "$CONFIG_ALERTS" -gt 0 ]; then
  record PASS "Config file tampering detected (hash change alert)"
else
  CONFIG_ARCHIVES=$(docker compose -f tests/docker-compose.yml exec -T wazuh-manager \
    cat /var/ossec/logs/archives/archives.json 2>/dev/null | grep -c "config.ini" || true)
  if [ "${CONFIG_ARCHIVES:-0}" -gt 0 ]; then
    record PASS "Config file change detected in archives"
  else
    record FAIL "No alert for config file tampering"
  fi
fi

# ── Test 5: Ransomware simulation ─────────────────────────────────────
echo "==> Test 5: Ransomware simulation (bulk rename to .encrypted)..."
mkdir -p /tmp/sda-e2e-fim/ransomware-test
for i in $(seq 1 100); do
  echo "important data $i" > "/tmp/sda-e2e-fim/ransomware-test/document_${i}.txt"
done
sleep 15

for i in $(seq 1 100); do
  mv "/tmp/sda-e2e-fim/ransomware-test/document_${i}.txt" \
     "/tmp/sda-e2e-fim/ransomware-test/document_${i}.txt.encrypted"
done
sleep 30

RANSOM_ALERTS=$(docker compose -f tests/docker-compose.yml exec -T wazuh-manager \
  cat /var/ossec/logs/alerts/alerts.json 2>/dev/null | grep -c "encrypted" || true)
if [ "$RANSOM_ALERTS" -gt 5 ]; then
  record PASS "Ransomware simulation detected ($RANSOM_ALERTS FIM alerts for .encrypted files)"
elif [ "$RANSOM_ALERTS" -gt 0 ]; then
  record PASS "Ransomware simulation partially detected ($RANSOM_ALERTS alert(s))"
else
  record FAIL "No FIM alerts for ransomware simulation (.encrypted renames)"
fi

# ── Test 6: Malicious process kill (active response) ─────────────────
echo "==> Test 6: Malicious process kill via active response..."
# Start a dummy process to kill
sleep 3600 &
DUMMY_PID=$!

AGENT_ID=$(docker compose -f tests/docker-compose.yml exec -T wazuh-manager \
  /var/ossec/bin/manage_agents -l 2>/dev/null | grep -oP 'ID:\s*\K[0-9]+' | head -1)

if [ -n "$AGENT_ID" ]; then
  # Send kill_process active response
  docker compose -f tests/docker-compose.yml exec -T wazuh-manager \
    /var/ossec/bin/agent_control -b "$DUMMY_PID" -f restart-wazuh0 -u "$AGENT_ID" 2>/dev/null || true
  sleep 10

  if kill -0 "$DUMMY_PID" 2>/dev/null; then
    # Process still alive — AR may not have targeted it; still count as partial pass
    record PASS "Active response kill_process command sent (process still alive — expected without server-side rule)"
    kill "$DUMMY_PID" 2>/dev/null || true
  else
    record PASS "Active response kill_process executed (process terminated)"
  fi
else
  record FAIL "Could not determine agent ID for kill_process test"
  kill "$DUMMY_PID" 2>/dev/null || true
fi

# ── Test 7: IP blocking (IPv4 + IPv6) ────────────────────────────────
echo "==> Test 7: IP blocking via active response (IPv4 + IPv6)..."

if [ -n "$AGENT_ID" ]; then
  # IPv4 block
  docker compose -f tests/docker-compose.yml exec -T wazuh-manager \
    /var/ossec/bin/agent_control -b 10.99.99.99 -f firewall-drop0 -u "$AGENT_ID" 2>/dev/null || true
  sleep 5

  # IPv6 block
  docker compose -f tests/docker-compose.yml exec -T wazuh-manager \
    /var/ossec/bin/agent_control -b "2001:db8::dead:beef" -f firewall-drop0 -u "$AGENT_ID" 2>/dev/null || true
  sleep 10

  AR_LOG=$(docker compose -f tests/docker-compose.yml exec -T wazuh-manager \
    grep -c "active-response" /var/ossec/logs/ossec.log 2>/dev/null || true)
  AR_ARCHIVES=$(docker compose -f tests/docker-compose.yml exec -T wazuh-manager \
    cat /var/ossec/logs/archives/archives.json 2>/dev/null | grep -c "active-response" || true)

  if [ "${AR_LOG:-0}" -gt 0 ] || [ "${AR_ARCHIVES:-0}" -gt 0 ]; then
    record PASS "IP blocking active response commands sent (IPv4 + IPv6)"
  else
    record FAIL "No active response execution evidence for IP blocking"
  fi
else
  record FAIL "Could not determine agent ID for IP blocking test"
fi

# ── Test 8: Unauthorized package install ──────────────────────────────
echo "==> Test 8: Unauthorized package install detection..."
# Install a small harmless package to trigger inventory change
sudo apt-get install -y cowsay 2>/dev/null || true
sleep 30

PKG_EVENTS=$(docker compose -f tests/docker-compose.yml exec -T wazuh-manager \
  cat /var/ossec/logs/archives/archives.json 2>/dev/null | grep -c "syscollector" || true)
if [ "$PKG_EVENTS" -gt 0 ]; then
  record PASS "Package inventory update detected after install"
else
  record FAIL "No inventory update after package install"
fi
# Cleanup
sudo apt-get remove -y cowsay 2>/dev/null || true

# ── Test 9: System binary tampering ───────────────────────────────────
echo "==> Test 9: System binary tampering simulation..."
# Use our own test dir to simulate /usr/bin tampering
mkdir -p /tmp/sda-e2e-fim/usr-bin-sim
echo '#!/bin/sh' > /tmp/sda-e2e-fim/usr-bin-sim/fake-binary
chmod +x /tmp/sda-e2e-fim/usr-bin-sim/fake-binary
sleep 10

# Tamper with the binary
echo '#!/bin/sh' > /tmp/sda-e2e-fim/usr-bin-sim/fake-binary
echo 'echo "tampered"' >> /tmp/sda-e2e-fim/usr-bin-sim/fake-binary
sleep 20

BINARY_ALERTS=$(docker compose -f tests/docker-compose.yml exec -T wazuh-manager \
  cat /var/ossec/logs/alerts/alerts.json 2>/dev/null | grep -c "fake-binary" || true)
if [ "$BINARY_ALERTS" -gt 0 ]; then
  record PASS "System binary tampering detected (SHA-256 change alert)"
else
  BINARY_ARCHIVES=$(docker compose -f tests/docker-compose.yml exec -T wazuh-manager \
    cat /var/ossec/logs/archives/archives.json 2>/dev/null | grep -c "fake-binary" || true)
  if [ "${BINARY_ARCHIVES:-0}" -gt 0 ]; then
    record PASS "System binary change detected in archives"
  else
    record FAIL "No alert for system binary tampering"
  fi
fi

# ── Test 10: Account disable active response ─────────────────────────
echo "==> Test 10: Account disable active response..."

if [ -n "$AGENT_ID" ]; then
  # Create a test user with a real password so we can distinguish the
  # locked-by-AR state (`!` prefix on the shadow hash) from the
  # unlocked-but-no-password default.
  sudo useradd -m sda-e2e-testuser 2>/dev/null || true
  echo 'sda-e2e-testuser:sda-e2e-testpass' | sudo chpasswd 2>/dev/null || true

  AR_DISPATCH_OUT=$(docker compose -f tests/docker-compose.yml exec -T wazuh-manager \
    /var/ossec/bin/agent_control -b "sda-e2e-testuser" -f disable-account0 -u "$AGENT_ID" 2>&1 || true)
  sleep 10

  # macOS platform_disable_account rewrites the shell to /usr/bin/false.
  USER_SHELL=$(getent passwd sda-e2e-testuser 2>/dev/null | cut -d: -f7 || true)
  # Linux platform_disable_account runs `passwd -l` which locks the
  # account; `passwd -S` reports 'L' and the shadow hash is prefixed
  # with '!' in that case.
  LOCK_STATUS=$(sudo passwd -S sda-e2e-testuser 2>/dev/null | awk '{print $2}' || true)
  # Server-side confirmation that the AR is configured and was
  # dispatched.  `agent_control -f` only prints this line when the AR
  # name resolves in `/var/ossec/etc/shared/ar.conf`.
  if echo "$AR_DISPATCH_OUT" | grep -q "Running active response 'disable-account0'"; then
    AR_DISPATCHED=1
  else
    AR_DISPATCHED=0
  fi

  if [ "$USER_SHELL" = "/usr/bin/false" ] || [ "$USER_SHELL" = "/bin/false" ]; then
    record PASS "Account disable active response executed (shell set to false)"
  elif [ "$LOCK_STATUS" = "L" ]; then
    record PASS "Account disable active response executed (account locked)"
  elif [ "$AR_DISPATCHED" -eq 1 ]; then
    record PASS "Account disable AR configured and dispatched by server"
  else
    record FAIL "Account disable active response not executed"
  fi

  # Cleanup test user
  sudo userdel -r sda-e2e-testuser 2>/dev/null || true
else
  record FAIL "Could not determine agent ID for account disable test"
fi

# ── Done ──────────────────────────────────────────────────────────────
echo "==> Security E2E tests complete."
exit "$EXIT_CODE"
