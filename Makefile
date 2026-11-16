SHELL := /bin/zsh
.DEFAULT_GOAL := help
.NOTPARALLEL:

WORKFLOW := Validation/Product/Scripts/developer-workflow.sh
OPERATIONAL_GOALS := check build install status test upgrade uninstall disable enable clean
REQUESTED_OPERATIONS := $(filter $(OPERATIONAL_GOALS),$(MAKECMDGOALS))

ifneq ($(word 2,$(REQUESTED_OPERATIONS)),)
$(error Request exactly one operational target per make invocation; build/install and lifecycle operations must not be combined or raced)
endif

.PHONY: help check build install status test upgrade uninstall disable enable clean

help:
	@$(WORKFLOW) help

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
