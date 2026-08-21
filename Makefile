.PHONY: install lint test smoke validate package

install:
	python -m pip install -e '.[dev]'

lint:
	ruff check src tests scripts

validate:
	python scripts/validate_manifest.py config/params_manifest.json

test: validate
	pytest -q

smoke: test
	python -m dynamic_cssc.cli smoke --output-dir results/smoke --seed 20260821

package:
	python scripts/package_review_bundle.py --stage local --output-dir artifacts
