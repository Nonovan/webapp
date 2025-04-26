.PHONY: setup audit update-waf check-certificates

setup:
  ./scripts/security_setup.sh $(ENV)

audit:
  ./scripts/security-audit.sh --full

update-waf:
  ./scripts/update-modsecurity-rules.sh

check-certificates:
  ./scripts/certificate-renew.sh --check-only
