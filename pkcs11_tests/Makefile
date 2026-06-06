.PHONY: install init test test-unit test-integration coverage clean reset

# ── Setup ─────────────────────────────────────────────────────────────
install:
	bash scripts/install_softhsm.sh

init:
	bash scripts/init_softhsm.sh

reset:
	bash scripts/reset_softhsm.sh

# ── Tests ─────────────────────────────────────────────────────────────
test:
	pytest

test-unit:
	pytest -m unit --no-cov

test-integration:
	pytest -m integration

test-fast:
	pytest -x --no-cov

coverage:
	pytest --cov=pkcs11_app --cov-report=html:coverage_html --cov-report=term-missing
	@echo "Coverage report: coverage_html/index.html"

# ── Helpers ───────────────────────────────────────────────────────────
show-env:
	@echo "PKCS11_MODULE_PATH  = $$PKCS11_MODULE_PATH"
	@echo "PKCS11_TOKEN_LABEL  = $$PKCS11_TOKEN_LABEL"
	@echo "PKCS11_USER_PIN     = $$PKCS11_USER_PIN"
	@echo "PKCS11_SO_PIN       = $$PKCS11_SO_PIN"

clean:
	rm -rf __pycache__ .pytest_cache coverage_html coverage.xml .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
