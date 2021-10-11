# Makefile

.PHONY: lint

DLIST:=missing-function-docstring,missing-module-docstring
DLIST:=$(DLIST),missing-class-docstring,too-few-public-methods
DLIST:=$(DLIST),too-many-arguments,too-many-locals,too-many-instance-attributes
DLIST:=$(DLIST),too-many-branches,too-many-statements,invalid-name
DLIST:=$(DLIST),too-many-return-statements,broad-except

FILE=ursecret.py

lint:
	pep8 $(FILE)
	PYTHONPATH=. pylint --disable=$(DLIST) \
		--include-naming-hint=y \
		--good-names=fp \
		$(FILE)

wheel:
	python3 setup.py sdist bdist_wheel

