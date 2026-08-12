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
VULN_SRC := src/vuln.c
STANDALONE_SRC := src/standalone_main.c
SERVER_SRC := src/server_main.c
BUILD := build

FIXTURES := \
	$(BUILD)/fixture1_none \
	$(BUILD)/fixture2_nx \
	$(BUILD)/fixture3_nx_canary \
	$(BUILD)/fixture4_nx_pie \
	$(BUILD)/fixture5_nx_pie_canary

# Phase 5's leak needs two interactions against the same address space
# (vulnerable() only ever calls read() once per process) — this forking
# server variant of fixture4 provides that; see src/server_main.c. Same
# protection flags as the matching non-server fixture, just a different
# harness. Phase 6's canary brute force needs the same thing: many
# connections against one long-lived process whose canary secret (chosen
# once at parent startup) is shared unchanged by every forked child.
SERVER_FIXTURES := \
	$(BUILD)/fixture3_nx_canary_server \
	$(BUILD)/fixture4_nx_pie_server \
	$(BUILD)/fixture5_nx_pie_canary_server

.PHONY: all clean

all: $(FIXTURES) $(SERVER_FIXTURES)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/fixture1_none: $(VULN_SRC) $(STANDALONE_SRC) | $(BUILD)
	$(CC) -no-pie -fno-stack-protector -z execstack -z norelro -o $@ $^

$(BUILD)/fixture2_nx: $(VULN_SRC) $(STANDALONE_SRC) | $(BUILD)
	$(CC) -no-pie -fno-stack-protector -z noexecstack -z norelro -o $@ $^

$(BUILD)/fixture3_nx_canary: $(VULN_SRC) $(STANDALONE_SRC) | $(BUILD)
	$(CC) -no-pie -fstack-protector-all -z noexecstack -z norelro -o $@ $^

$(BUILD)/fixture4_nx_pie: $(VULN_SRC) $(STANDALONE_SRC) | $(BUILD)
	$(CC) -pie -fPIC -fno-stack-protector -z noexecstack -z norelro -o $@ $^

$(BUILD)/fixture5_nx_pie_canary: $(VULN_SRC) $(STANDALONE_SRC) | $(BUILD)
	$(CC) -pie -fPIC -fstack-protector-all -z noexecstack -z norelro -o $@ $^

$(BUILD)/fixture3_nx_canary_server: $(VULN_SRC) $(SERVER_SRC) | $(BUILD)
	$(CC) -no-pie -fstack-protector-all -z noexecstack -z norelro -o $@ $^

$(BUILD)/fixture4_nx_pie_server: $(VULN_SRC) $(SERVER_SRC) | $(BUILD)
	$(CC) -pie -fPIC -fno-stack-protector -z noexecstack -z norelro -o $@ $^

$(BUILD)/fixture5_nx_pie_canary_server: $(VULN_SRC) $(SERVER_SRC) | $(BUILD)
	$(CC) -pie -fPIC -fstack-protector-all -z noexecstack -z norelro -o $@ $^

clean:
	rm -rf $(BUILD)
