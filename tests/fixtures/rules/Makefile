# A file named Makefile has no extension, so it reaches scan_makefile only
# through the basename branch of classify_file.
#
# The value is unquoted. The universal CWE-798 rule requires a quote after
# the '=', so it does not see this at all — which is why scan_makefile
# carries its own credential rule.
REGISTRY_PASSWORD = s3cret-registry-pw

all:
	$(CC) -o widget src/main.c
