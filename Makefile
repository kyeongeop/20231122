ROOT := $(CURDIR)
GO := $(shell if [ -x "$(ROOT)/.tools/go/bin/go" ]; then echo "$(ROOT)/.tools/go/bin/go"; else echo go; fi)

.PHONY: all experiment fuzz report verify show test clean

all: experiment fuzz report verify

experiment:
	$(GO) run ./cmd/pathaliaslab run --db artifacts/experiment.db

fuzz:
	FUZZ_SECONDS="$(or $(FUZZ_SECONDS),10)" ./scripts/run_fuzz.sh "$(or $(FUZZ_SECONDS),10)"

report:
	$(GO) run ./cmd/pathaliaslab report --db artifacts/experiment.db --artifacts artifacts

verify:
	$(GO) run ./cmd/pathaliaslab verify --db artifacts/experiment.db

show:
	$(GO) run ./cmd/pathaliaslab show --db artifacts/experiment.db --run "$(or $(RUN),primary_cancel)"

test:
	$(GO) test ./...

clean:
	rm -rf .build artifacts/experiment.db artifacts/experiment.db-wal artifacts/experiment.db-shm
	rm -rf artifacts/fuzz artifacts/evidence artifacts/report.json artifacts/report.md
