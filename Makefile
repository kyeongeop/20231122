GO ?= go

.PHONY: all test fuzz libfuzzer demo verify clean

all:
	$(GO) build ./...

test:
	$(GO) test ./...

fuzz:
	$(GO) test ./internal/stream/ -run='^$$' -fuzz=FuzzParse -fuzztime=30s
	$(GO) test ./internal/reconcile/ -run='^$$' -fuzz=FuzzReconcileDeterminism -fuzztime=20s
	$(GO) test ./internal/export/ -run='^$$' -fuzz=FuzzBundleRoundTrip -fuzztime=20s

libfuzzer:
	bash scripts/build_libfuzzer.sh
	fuzz/bin/truncstream_fuzz fuzz/corpus_libfuzzer -max_total_time=60

demo:
	$(GO) run ./cmd/truncstream demo -dir artifacts/demo -frames 27 -suspend-after 8

verify:
	$(GO) run ./cmd/truncstream verify-bundle artifacts/demo/review-bundle.tar
	$(GO) run ./cmd/truncstream verify-artifact artifacts/demo/resumable.sqlite

clean:
	rm -rf fuzz/bin artifacts/demo*
