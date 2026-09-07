.PHONY: test vectors benchmark

test:
	PYTHONPATH=src python -m unittest discover -s tests -v

vectors:
	python scripts/generate_vectors.py > test-vectors.json

benchmark:
	python scripts/benchmark.py | tee benchmark-results.txt

