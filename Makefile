.PHONY: check test coverage render new

check:            ## schema + lint + logic tests over every rule (the CI gate)
	python tools/validate.py

test: check       ## gate + tooling tests
	python -m pytest -q

coverage:         ## regenerate coverage/, gaps and the ATT&CK Navigator layer
	python tools/coverage.py

render:           ## prod sentinel-kql rules -> infra/sentinel/rules.generated.json
	python tools/sentinel_deploy.py render

new:              ## copy the template: make new ID=DET-0042 NAME=my-rule
	cp docs/TEMPLATE.yml detections/$(shell echo $(ID) | tr A-Z a-z)-$(NAME).yml
