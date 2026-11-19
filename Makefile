SHELL := /bin/zsh
.DEFAULT_GOAL := help
.NOTPARALLEL:

WORKFLOW := Validation/Product/Scripts/developer-workflow.sh
RELEASE_GOALS := release-prepare release-rebuild release-check release-unsigned release-repeatability release release-verify release-test
OPERATIONAL_GOALS := check build install status test upgrade uninstall disable enable clean $(RELEASE_GOALS)
REQUESTED_OPERATIONS := $(filter $(OPERATIONAL_GOALS),$(MAKECMDGOALS))

ifneq ($(word 2,$(REQUESTED_OPERATIONS)),)
$(error Request exactly one operational target per make invocation; development, lifecycle and release operations must not be combined)
endif

.PHONY: help check build install status test upgrade uninstall disable enable clean release-help $(RELEASE_GOALS)

help:
	@$(WORKFLOW) help
	@/usr/bin/python3 -B Release/release.py help

check:
	@$(WORKFLOW) check
	@Validation/Product/Scripts/test-build-development-slot.sh
	@Validation/Product/Scripts/test-developer-workflow.sh
	@Validation/Product/Scripts/test-pilot-lifecycle.sh
	@Validation/Product/Scripts/test-pilot-upgrade-root.sh
	@Validation/Product/Scripts/test-pilot-lifecycle-privileged-static.sh
	@Validation/Product/Scripts/test-scan-secret-logs.sh

build:
	@$(WORKFLOW) build

install:
	@$(WORKFLOW) install

status:
	@$(WORKFLOW) status

test:
	@Validation/Product/Scripts/test-build-development-slot.sh
	@Validation/Product/Scripts/test-developer-workflow.sh
	@Validation/Product/Scripts/test-pilot-lifecycle.sh
	@Validation/Product/Scripts/test-pilot-upgrade-root.sh
	@Validation/Product/Scripts/test-pilot-lifecycle-privileged-static.sh
	@Validation/Product/Scripts/test-scan-secret-logs.sh

upgrade uninstall disable enable clean:
	@$(WORKFLOW) $@

release-help:
	@/usr/bin/python3 -B Release/release.py help

release-check release-unsigned release-repeatability release-verify:
	@/usr/bin/python3 -B Release/release.py $(@:release-%=%)

release-prepare:
	@/usr/bin/python3 -B Release/release.py prepare-credential

release-rebuild:
	@/usr/bin/python3 -B Release/release.py rebuild-credential

release:
	@/usr/bin/python3 -B Release/release.py release

release-test:
	@/usr/bin/python3 -B -m unittest discover -s Release -p 'test_*.py' -v
