# Ordinary build rules. Every construct here is legitimate and common,
# and none of it may be reported.
CC      := gcc
CFLAGS  := -Wall -Wextra -O2
BUILD   := build

# $(shell ...) is normal; only a $(shell ...) that FETCHES is suspicious.
GIT_REV := $(shell git rev-parse --short HEAD)
CFLAGS  += $(shell pkg-config --cflags glib-2.0)

# Credentials taken from the environment, never written in the file.
API_KEY ?=
DEPLOY_TOKEN = $(CI_DEPLOY_TOKEN)

.PHONY: all clean fetch

all: $(BUILD)/widget

$(BUILD)/widget: src/main.c
	$(CC) $(CFLAGS) -o $@ $<

# Downloading is fine; it is piping into a shell that is not.
fetch:
	curl -fsSL https://example.invalid/data.json -o $(BUILD)/data.json

# Recursive delete of a build directory is the most ordinary rule there is.
clean:
	rm -rf $(BUILD)
	rm -rf dist .pytest_cache
