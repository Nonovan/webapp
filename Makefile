# Cloud Infrastructure Platform - Build and Maintenance Tasks
#
# This Makefile provides convenient shortcuts for common operational tasks
# including setup, security, monitoring, and database maintenance.

# Default environment if not specified
ENV ?= development

#
# Security and Compliance Tasks
#
.PHONY: setup audit update-waf check-certificates security-baseline compliance-check verify-integrity list-baseline backup-baseline compare-baselines check-file-integrity analyze-files

setup:
    ./scripts/security/security_setup.sh $(ENV)

audit:
    ./scripts/security/security-audit.sh --full

update-waf:
    ./scripts/security/update-modsecurity-rules.sh

check-certificates:
    ./scripts/security/certificate-renew.sh --check-only

security-baseline:
    ./scripts/security/file_integrity_checker.sh --update-baseline

# New file integrity management commands
verify-integrity:
    flask integrity verify $(BASELINE_PATH) $(VERBOSE)

list-baseline:
    flask integrity list-baseline $(BASELINE_PATH) $(FILTER) $(FORMAT) $(SORT)

backup-baseline:
    flask integrity backup-baseline $(BASELINE_PATH) $(BACKUP_DIR) $(COMMENT)

compare-baselines:
    flask integrity compare-baselines $(BASELINE1) $(BASELINE2) $(FORMAT)

check-file-integrity:
    flask integrity check-file $(FILE_PATH) $(BASELINE) $(ALGORITHM)

analyze-files:
    flask integrity analyze $(PATH) $(PATTERN) $(LIMIT)

compliance-check:
    ./scripts/compliance/validate_compliance.sh --environment $(ENV) --report compliance-report.json

#
# Database Tasks
#
.PHONY: db-optimize db-backup db-verify db-migration

db-optimize:
    ./scripts/database/optimize.sh --env $(ENV)

db-backup:
    ./scripts/database/backup.sh --env $(ENV)

db-verify:
    ./scripts/database/verify-backups.sh --env $(ENV)

db-migrate:
    flask db upgrade

#
# Resource Configuration Tasks
#
.PHONY: configure-resources configure-connections env-sync

configure-resources:
    ./scripts/deployment/config/configure_resources.sh --environment $(ENV)

configure-connections:
    ./scripts/deployment/config/configure_connections.sh --environment $(ENV)

env-sync:
    ./scripts/maintenance/env_sync.sh --source $(SRC_ENV) --target $(ENV)

#
# Testing and Development Tasks
#
.PHONY: test lint format docs dev-setup

test:
    python -m pytest -xvs $(TEST_ARGS)

lint:
    ./scripts/utils/dev_tools/lint.sh --check

format:
    ./scripts/utils/dev_tools/lint.sh --fix

docs:
    ./scripts/utils/dev_tools/generate_docs.sh

dev-setup:
    ./scripts/utils/dev_tools/setup_dev_environment.sh

#
# Monitoring Tasks
#
.PHONY: health-check performance-test monitor

health-check:
    ./scripts/monitoring/health-check.sh --environment $(ENV)

performance-test:
    ./scripts/monitoring/tests/performance-test.sh $(ENV)

monitor:
    ./scripts/monitoring/config/update-monitoring.sh --environment $(ENV)

#
# Deployment Tasks
#
.PHONY: deploy collect-static rollback

deploy:
    ./scripts/deployment/deploy.sh --environment $(ENV)

collect-static:
    ./scripts/deployment/core/collect_static.sh

rollback:
    ./scripts/deployment/rollback.sh --environment $(ENV)

#
# Maintenance Tasks
#
.PHONY: cleanup rotate-logs apply-security-updates

cleanup:
    ./scripts/maintenance/cleanup.sh --environment $(ENV)

rotate-logs:
    ./scripts/maintenance/rotate_logs.sh

apply-security-updates:
    ./scripts/security/apply_security_updates.sh --environment $(ENV)

#
# Help target
#
.PHONY: help

help:
    @echo "Cloud Infrastructure Platform Makefile"
    @echo ""
    @echo "Security and Compliance:"
    @echo "  make setup               - Set up security configurations for environment"
    @echo "  make audit               - Run comprehensive security audit"
    @echo "  make update-waf          - Update WAF rules"
    @echo "  make check-certificates  - Check certificate validity"
    @echo "  make security-baseline   - Update file integrity baseline"
    @echo "  make verify-integrity    - Verify file integrity against baseline"
    @echo "  make list-baseline       - List contents of integrity baseline file"
    @echo "  make backup-baseline     - Create backup of integrity baseline"
    @echo "  make compare-baselines BASELINE1=path1 BASELINE2=path2 - Compare two baseline files"
    @echo "  make check-file-integrity FILE_PATH=path - Check specific file against baseline"
    @echo "  make analyze-files       - Analyze files for potential integrity risks"
    @echo "  make compliance-check    - Validate compliance requirements"
    @echo ""
    @echo "Database:"
    @echo "  make db-optimize         - Run database optimization"
    @echo "  make db-backup           - Back up database"
    @echo "  make db-verify           - Verify database backups"
    @echo "  make db-migrate          - Run database migrations"
    @echo ""
    @echo "Resource Configuration:"
    @echo "  make configure-resources - Configure computing resources"
    @echo "  make configure-connections - Configure service connections"
    @echo "  make env-sync SRC_ENV=source_env - Sync environment configurations"
    @echo ""
    @echo "Testing and Development:"
    @echo "  make test [TEST_ARGS='...'] - Run tests"
    @echo "  make lint                   - Check code quality"
    @echo "  make format                 - Fix code formatting"
    @echo "  make docs                   - Generate documentation"
    @echo "  make dev-setup              - Set up development environment"
    @echo ""
    @echo "Monitoring:"
    @echo "  make health-check         - Run health checks"
    @echo "  make performance-test     - Run performance tests"
    @echo "  make monitor              - Update monitoring configuration"
    @echo ""
    @echo "Deployment:"
    @echo "  make deploy               - Deploy application"
    @echo "  make collect-static       - Collect and process static files"
    @echo "  make rollback             - Roll back to previous version"
    @echo ""
    @echo "Maintenance:"
    @echo "  make cleanup              - Run system cleanup"
    @echo "  make rotate-logs          - Rotate log files"
    @echo "  make apply-security-updates - Apply security updates"
    @echo ""
    @echo "Usage:"
    @echo "  ENV=production make deploy   - Deploy to production environment"
    @echo "  make verify-integrity VERBOSE='-v'   - Run integrity verification with verbose output"
    @echo "  make list-baseline FILTER='-f core/' - List baseline files in core directory"
    @echo "  make backup-baseline COMMENT='pre-deployment' - Back up baseline with comment"
    @echo "  make check-file-integrity FILE_PATH=app.py ALGORITHM='--algorithm sha256' - Check specific file"
    @echo "  make compare-baselines BASELINE1=baseline1.json BASELINE2=baseline2.json - Compare baselines"
