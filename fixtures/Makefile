# Builds the graduated protection-tier fixtures described in PRD.md §7 Phase 0.
# All five fixtures share the same vulnerable source (src/vuln.c) — only the
# gcc/ld protection flags differ between tiers, so the ladder isolates each
# mitigation independently. RELRO is disabled uniformly (-z norelro) since it
# is not one of the five graduated tiers.
#
# Must be built on x86-64 Linux (see .devcontainer/) — Debian's gcc defaults
# to PIE + stack-protector-strong + noexecstack, so tiers 1/2 explicitly
# override those hardened defaults to get a genuinely unprotected baseline.

CC := gcc
SRC := src/vuln.c
BUILD := build

FIXTURES := \
	$(BUILD)/fixture1_none \
	$(BUILD)/fixture2_nx \
	$(BUILD)/fixture3_nx_canary \
	$(BUILD)/fixture4_nx_pie \
	$(BUILD)/fixture5_nx_pie_canary

.PHONY: all clean

all: $(FIXTURES)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/fixture1_none: $(SRC) | $(BUILD)
	$(CC) -no-pie -fno-stack-protector -z execstack -z norelro -o $@ $<

$(BUILD)/fixture2_nx: $(SRC) | $(BUILD)
	$(CC) -no-pie -fno-stack-protector -z noexecstack -z norelro -o $@ $<

$(BUILD)/fixture3_nx_canary: $(SRC) | $(BUILD)
	$(CC) -no-pie -fstack-protector-all -z noexecstack -z norelro -o $@ $<

$(BUILD)/fixture4_nx_pie: $(SRC) | $(BUILD)
	$(CC) -pie -fPIC -fno-stack-protector -z noexecstack -z norelro -o $@ $<

$(BUILD)/fixture5_nx_pie_canary: $(SRC) | $(BUILD)
	$(CC) -pie -fPIC -fstack-protector-all -z noexecstack -z norelro -o $@ $<

clean:
	rm -rf $(BUILD)
