.PHONY: codegen codegen-check

# Regenerate analytics.ts from analytics.go via tygo. Run after editing
# any Go type that web consumes.
codegen:
	go run github.com/gzuidhof/tygo@latest generate

# CI gate: regenerate and fail if the output drifts from what's
# committed. Catches "forgot to run codegen before commit" PRs.
codegen-check: codegen
	@if ! git diff --quiet --exit-code analytics.ts; then \
		echo "analytics.ts is stale — run \`make codegen\` in veto-core/config"; \
		git diff analytics.ts; \
		exit 1; \
	fi
