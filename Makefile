.PHONY: test experiment verify clean

test:
	./scripts/test.sh

experiment:
	./scripts/run_all.sh

verify:
	./.build/depthlab verify \
		--db artifacts/evidence.sqlite \
		--report artifacts/report.json \
		--manifest artifacts/manifest.sha256

clean:
	rm -rf .build .tmp artifacts/evidence.sqlite artifacts/evidence.sqlite-journal
	rm -f artifacts/report.json artifacts/report.md artifacts/manifest.sha256
