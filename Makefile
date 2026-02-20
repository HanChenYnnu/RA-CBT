PYTHON ?= python

.PHONY: setup test lint fmt run all

setup:
	$(PYTHON) -m pip install --no-build-isolation --no-deps -e .

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check .

fmt:
	$(PYTHON) -m ruff format .

run:
	$(PYTHON) -m uvicorn gateway.app:app --reload

all:
	bash scripts/run_all.sh
