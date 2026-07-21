CC ?= cc
CPPFLAGS ?= -Iinclude
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror
LDLIBS ?= -lcrypto
BUILD := build
SOURCES := src/sha256.c src/ioc.c src/signing.c src/cli.c
OBJECTS := $(SOURCES:src/%.c=$(BUILD)/%.o)

.PHONY: all clean test sanitize

all: $(BUILD)/threatcore

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD)/threatcore: $(OBJECTS)
	$(CC) $(CFLAGS) $^ $(LDLIBS) -o $@

$(BUILD)/test_sha256: tests/test_sha256.c src/sha256.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@

$(BUILD)/test_ioc: tests/test_ioc.c src/ioc.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@

$(BUILD)/test_signing: tests/test_signing.c src/signing.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ $(LDLIBS) -o $@

test: $(BUILD)/test_sha256 $(BUILD)/test_ioc $(BUILD)/test_signing $(BUILD)/threatcore
	$(BUILD)/test_sha256
	$(BUILD)/test_ioc
	$(BUILD)/test_signing
	printf 'abc' | $(BUILD)/threatcore hash --stdin | grep -q '^ba7816bf8f01cfea'
	@echo "native integration tests passed"

sanitize:
	$(MAKE) clean
	ASAN_OPTIONS=detect_leaks=0 $(MAKE) CFLAGS='-std=c11 -O1 -g -Wall -Wextra -Wpedantic -Werror -fno-omit-frame-pointer -fsanitize=address,undefined' test

clean:
	rm -rf $(BUILD)
