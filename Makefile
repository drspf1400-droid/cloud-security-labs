.PHONY: test demo check

test:
	python3 -m pytest -q

demo:
	./scripts/demo_security_assurance_mvp.sh

check:
	bash -n scripts/demo_security_assurance_mvp.sh
	git diff --check
