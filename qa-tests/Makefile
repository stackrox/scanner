.PHONY: all
all: style test

###########
## Style ##
###########
.PHONY: style
style:
	@echo "+ $@"
	@gradle --continue codenarcMain codenarcTest ; \
	STATUS=$$? ; \
	if [ $$STATUS -ne 0 ]; then \
	    cat build/reports/codenarc/main.txt build/reports/codenarc/test.txt >&2 2>/dev/null ; \
	fi ; \
	exit $$STATUS

.PHONY: proto-generated-srcs
proto-generated-srcs:
	@echo "+ $@"
	-rm -r src/main/proto
	gradle generateProto generateTestProto

.PHONY: clean-generated-srcs
clean-generated-srcs:
	@echo "+ $@"
	git clean -xdf build/generated

.PHONY: test
test: proto-generated-srcs
	@echo "+ $@"
	gradle test