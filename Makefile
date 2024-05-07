# Use one shell for the whole recipe, instead of per-line
.ONESHELL:
# Use bash in strict mode
SHELL := bash
.SHELLFLAGS = -eu -o pipefail -c

# Sane makefile settings to avoid the unexpected
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules --no-builtin-variables

# Provide a command to source the env.sh file if any
source ?= source env.sh || true

# All the ex files
ex_files = $(shell find . -name '*.ex')
# All the exs files
exs_files = $(shell find . -name '*.exs')

deps: mix.exs mix.lock
	@echo "📦 Download the project dependencies"
	mix deps.get
	touch $@

doc: deps $(ex_files)
	@echo "📚 Create the documentation"
	mix docs
	touch $@

.PHONY: qa dialyzer dialixir
dialyzer: qa
dialixir: qa
qa: deps
	@echo "🕵️‍♀️ Run dialyzer"
	mix dialyzer

.PHONY: test
test: deps
	@echo "🧪 Run the tests"
	mix test

.PHONY: test-watch
test-watch: deps
	@echo "🥽 Run the tests on changes"
	mix test.watch

.PHONY: test-tezos
test-tezos: deps
	@echo "🧪 Run the tezos tests"
	mix test --only tezos

.PHONY: coverage
coverage: cover
cover: deps $(ex_files) $(exs_files)
	@echo "🔍 Generate the coverage report"
	mix coveralls.html
	touch $@

clean-all:
	@echo "🗑  Clean all artifacts"
	rm -rf deps _build cover doc
