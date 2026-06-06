.PHONY: install init test test-unit test-integration test-load test-perf \
        coverage clean reset \
        build-softhsm2 build-softhsm2-coverage softhsm2-coverage-report \
        env-local

# ── System SoftHSM2 setup ─────────────────────────────────────────────
install:
	bash scripts/install_softhsm.sh

init:
	bash scripts/init_softhsm.sh

reset:
	bash scripts/reset_softhsm.sh

# ── Build SoftHSM2 from source ────────────────────────────────────────
## Clone sources (one-time):
##   git clone --depth=1 --branch 2.6.1 \
##     https://github.com/opendnssec/SoftHSMv2.git softhsm2_src

build-softhsm2:
	bash scripts/build_softhsm2.sh

build-softhsm2-coverage:
	bash scripts/build_softhsm2.sh --with-coverage

env-local:
	@echo "Run:  source scripts/env_local_softhsm2.sh"

softhsm2-coverage-report:
	bash scripts/softhsm2_coverage_report.sh

# ── Tests ─────────────────────────────────────────────────────────────
test:
	pytest

test-unit:
	pytest -m unit --no-cov

test-integration:
	pytest -m integration

test-load:
	pytest -m load --no-cov -v

test-perf:
	pytest tests/test_perf_all_mechanisms.py --no-cov -v -s

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
	rm -rf __pycache__ .pytest_cache coverage_html coverage.xml .coverage perf_report.xlsx
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

clean-build:
	rm -rf softhsm2_build softhsm2_install softhsm2_tokens softhsm2_local.conf \
	       softhsm2_coverage.info softhsm2_coverage_html

