#!/usr/bin/env python3
"""Unit tests for transit/rx.py. Every expected value was obtained by running GNU grep 3.11 (LC_ALL=C) on this machine,
not from the POSIX text: ``CASES`` is a recorded table, and ``LiveGrep`` re-runs each row through the real grep so that the
table cannot drift from what grep does.

    python3 -I tests/conformance/test_rx.py            (or: python3 -m unittest tests.conformance.test_rx)

The mutation check in the report uses RX_ROOT to point these tests (and pattern_fuzz.py) at a mutated copy of transit/rx.py.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(os.environ.get("RX_ROOT") or Path(__file__).resolve().parents[2])
sys.path.insert(0, str(ROOT))
from transit import rx  # noqa: E402

GREP = shutil.which("grep")
ENV = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"}


def live_grep_available() -> bool:
    if not GREP:
        return False
    try:
        out = subprocess.run([GREP, "--version"], capture_output=True, env=ENV).stdout.decode()
    except OSError:
        return False
    return "GNU grep" in out


def grep_q(pat: str, data: bytes, ci: bool = False, extra: tuple[str, ...] = ()) -> int:
    return subprocess.run([GREP, "-qE", *(["-i"] if ci else []), *extra, "-e", pat], input=data, capture_output=True,
                          env=ENV).returncode


# (group, pattern, ignore_case, input, grep -qE says "a line matches")   -- recorded from grep (GNU grep) 3.11, LC_ALL=C
CASES = [
    ('posix class', '[[:space:]]', False, b'a b', True),
    ('posix class', '[[:space:]]', False, b'a\tb', True),
    ('posix class', '[[:space:]]', False, b'ab', False),
    ('posix class', '[[:space:]]', False, b'a\rb', True),
    ('posix class', '[[:space:]]', False, b'a\x0bb', True),
    ('posix class', '[[:space:]]', False, b'a\x0cb', True),
    ('posix class', '[[:space:]]', False, b'', False),
    ('posix class', '[[:space:]]', False, b' ', True),
    ('posix class', '[[:alpha:]]+', False, b'abc', True),
    ('posix class', '[[:alpha:]]+', False, b'123', False),
    ('posix class', '[[:alpha:]]+', False, b'_', False),
    ('posix class', '[[:alpha:]]+', False, b'a1', True),
    ('posix class', '^[[:digit:]]+$', False, b'123', True),
    ('posix class', '^[[:digit:]]+$', False, b'12a', False),
    ('posix class', '^[[:digit:]]+$', False, b'', False),
    ('posix class', '^[[:digit:]]+$', False, b'0', True),
    ('posix class', '[[:upper:]]', False, b'a', False),
    ('posix class', '[[:upper:]]', False, b'A', True),
    ('posix class -i', '[[:upper:]]', True, b'a', True),
    ('posix class -i', '[[:upper:]]', True, b'A', True),
    ('posix class -i', '[[:upper:]]', True, b'1', False),
    ('posix class', '[[:punct:]]', False, b'a', False),
    ('posix class', '[[:punct:]]', False, b'!', True),
    ('posix class', '[[:punct:]]', False, b'_', True),
    ('posix class', '[[:punct:]]', False, b' ', False),
    ('posix class', '[[:punct:]]', False, b'~', True),
    ('posix class', '[[:cntrl:]]', False, b'a', False),
    ('posix class', '[[:cntrl:]]', False, b'\x01', True),
    ('posix class', '[[:cntrl:]]', False, b'\x7f', True),
    ('posix class', '[[:cntrl:]]', False, b'\t', True),
    ('posix class', '[[:print:]]+$', False, b'abc', True),
    ('posix class', '[[:print:]]+$', False, b'a\x01', False),
    ('posix class', '[[:print:]]+$', False, b'\xe9', False),
    ('posix class', '[[:xdigit:]]{4}', False, b'dead', True),
    ('posix class', '[[:xdigit:]]{4}', False, b'deaf', True),
    ('posix class', '[[:xdigit:]]{4}', False, b'beef0', True),
    ('posix class', '[[:xdigit:]]{4}', False, b'xyz1', False),
    ('bracket ]', '[^]x]', False, b']', False),
    ('bracket ]', '[^]x]', False, b'x', False),
    ('bracket ]', '[^]x]', False, b'y', True),
    ('bracket ]', '[^]x]', False, b']x', False),
    ('bracket ]', '[^]x]', False, b'a', True),
    ('bracket ]', '[]x]', False, b']', True),
    ('bracket ]', '[]x]', False, b'x', True),
    ('bracket ]', '[]x]', False, b'y', False),
    ('bracket ]', '[]]', False, b']', True),
    ('bracket ]', '[]]', False, b'a', False),
    ('bracket ]', '[^]]', False, b']', False),
    ('bracket ]', '[^]]', False, b'a', True),
    ('bracket ]', '[^]]', False, b']]', False),
    ('bracket backslash', '[a\\]', False, b'a', True),
    ('bracket backslash', '[a\\]', False, b'\\', True),
    ('bracket backslash', '[a\\]', False, b'b', False),
    ('bracket backslash', '[a\\]', False, b'a\\', True),
    ('bracket backslash', '[\\]]', False, b']', False),
    ('bracket backslash', '[\\]]', False, b'\\', False),
    ('bracket backslash', '[\\]]', False, b'\\]', True),
    ('bracket backslash', '[\\]]', False, b'a', False),
    ('bracket backslash', '[\\s]', False, b's', True),
    ('bracket backslash', '[\\s]', False, b'\\', True),
    ('bracket backslash', '[\\s]', False, b' ', False),
    ('bracket backslash', '[\\s]', False, b'\t', False),
    ('bracket backslash', '[\\s]', False, b'a', False),
    ('bracket backslash', '[^\\s]', False, b's', False),
    ('bracket backslash', '[^\\s]', False, b'\\', False),
    ('bracket backslash', '[^\\s]', False, b' ', True),
    ('bracket backslash', '[^\\s]', False, b'a', True),
    ('bracket backslash', '[\\w]', False, b'w', True),
    ('bracket backslash', '[\\w]', False, b'\\', True),
    ('bracket backslash', '[\\w]', False, b'a', False),
    ('bracket backslash', '[\\w]', False, b'_', False),
    ('bracket backslash', '["\\s]+x', False, b'"x', True),
    ('bracket backslash', '["\\s]+x', False, b's x', False),
    ('bracket backslash', '["\\s]+x', False, b'\\x', True),
    ('bracket backslash', '["\\s]+x', False, b' x', False),
    ('bracket backslash', '["\\s]+x', False, b'x', False),
    ('bracket hyphen', '[a-]', False, b'a', True),
    ('bracket hyphen', '[a-]', False, b'-', True),
    ('bracket hyphen', '[a-]', False, b'b', False),
    ('bracket hyphen', '[-a]', False, b'a', True),
    ('bracket hyphen', '[-a]', False, b'-', True),
    ('bracket hyphen', '[-a]', False, b'b', False),
    ('bracket hyphen', '[%--]', False, b'-', True),
    ('bracket hyphen', '[%--]', False, b'%', True),
    ('bracket hyphen', '[%--]', False, b'+', True),
    ('bracket hyphen', '[%--]', False, b'a', False),
    ('bracket hyphen', '[a-c]x', False, b'bx', True),
    ('bracket hyphen', '[a-c]x', False, b'dx', False),
    ('bracket hyphen', '[a-c]x', False, b'-x', False),
    ('bracket hyphen', '[]-a]', False, b']', True),
    ('bracket hyphen', '[]-a]', False, b'^', True),
    ('bracket hyphen', '[]-a]', False, b'a', True),
    ('bracket hyphen', '[]-a]', False, b'b', False),
    ('bracket hyphen', '[]-a]', False, b'-', False),
    ('bracket caret', '[a^]', False, b'a', True),
    ('bracket caret', '[a^]', False, b'^', True),
    ('bracket caret', '[a^]', False, b'b', False),
    ('bracket caret', '[^^]', False, b'^', False),
    ('bracket caret', '[^^]', False, b'a', True),
    ('bracket caret', '[^^]', False, b'^^', False),
    ('bracket', '[.]', False, b'.', True),
    ('bracket', '[.]', False, b'a', False),
    ('bracket', '[$]', False, b'$', True),
    ('bracket', '[$]', False, b'a', False),
    ('bracket', '[*+?{}()|]', False, b'*', True),
    ('bracket', '[*+?{}()|]', False, b'+', True),
    ('bracket', '[*+?{}()|]', False, b'?', True),
    ('bracket', '[*+?{}()|]', False, b'{', True),
    ('bracket', '[*+?{}()|]', False, b'}', True),
    ('bracket', '[*+?{}()|]', False, b'(', True),
    ('bracket', '[*+?{}()|]', False, b')', True),
    ('bracket', '[*+?{}()|]', False, b'|', True),
    ('bracket', '[*+?{}()|]', False, b'a', False),
    ('bracket', '[[]', False, b'[', True),
    ('bracket', '[[]', False, b'a', False),
    ('bracket', '[a-z0-9_.-]+@', False, b'foo.bar@', True),
    ('bracket', '[a-z0-9_.-]+@', False, b'@', False),
    ('bracket', '[a-z0-9_.-]+@', False, b'a b@', True),
    ('shorthand', '\\s', False, b' ', True),
    ('shorthand', '\\s', False, b'\t', True),
    ('shorthand', '\\s', False, b'a', False),
    ('shorthand', '\\s', False, b'\x0b', True),
    ('shorthand', '\\S', False, b' ', False),
    ('shorthand', '\\S', False, b'a', True),
    ('shorthand', '\\S', False, b'\t', False),
    ('shorthand', 'a\\s+b', False, b'a b', True),
    ('shorthand', 'a\\s+b', False, b'a\tb', True),
    ('shorthand', 'a\\s+b', False, b'ab', False),
    ('shorthand', 'a\\s+b', False, b'a  \t b', True),
    ('shorthand', '\\w+', False, b'abc', True),
    ('shorthand', '\\w+', False, b'___', True),
    ('shorthand', '\\w+', False, b'-', False),
    ('shorthand', '\\w+', False, b'a-', True),
    ('shorthand', '\\W', False, b'abc', False),
    ('shorthand', '\\W', False, b'_', False),
    ('shorthand', '\\W', False, b'a b', True),
    ('shorthand', '\\W', False, b'-', True),
    ('shorthand', '^\\w+$', False, b'abc', True),
    ('shorthand', '^\\w+$', False, b'a-c', False),
    ('shorthand', '^\\w+$', False, b'', False),
    ('shorthand', '^\\w+$', False, b'a_1', True),
    ('shorthand', '\\d', False, b'5', False),
    ('shorthand', '\\d', False, b'd', True),
    ('shorthand', '\\d', False, b'd5', True),
    ('shorthand', '\\D', False, b'5', False),
    ('shorthand', '\\D', False, b'd', False),
    ('shorthand', '\\D', False, b'x', False),
    ('shorthand', '[0-9]\\d', False, b'5d', True),
    ('shorthand', '[0-9]\\d', False, b'55', False),
    ('shorthand', '[0-9]\\d', False, b'5', False),
    ('shorthand', '\\x41', False, b'A', False),
    ('shorthand', '\\x41', False, b'x41', True),
    ('shorthand', '\\x41', False, b'x', False),
    ('shorthand', 'a\\tb', False, b'a\tb', False),
    ('shorthand', 'a\\tb', False, b'atb', True),
    ('shorthand', 'a\\nb', False, b'anb', True),
    ('shorthand', 'a\\nb', False, b'a\nb', False),
    ('word boundary', '\\bfoo\\b', False, b'foo', True),
    ('word boundary', '\\bfoo\\b', False, b'a foo b', True),
    ('word boundary', '\\bfoo\\b', False, b'foobar', False),
    ('word boundary', '\\bfoo\\b', False, b'barfoo', False),
    ('word boundary', '\\bfoo\\b', False, b'foo_', False),
    ('word boundary', '\\bfoo\\b', False, b'-foo-', True),
    ('word boundary', '\\bfoo\\b', False, b'foo.bar', True),
    ('word boundary', '\\bfoo\\b', False, b'_foo', False),
    ('word boundary', '\\bfoo', False, b'foo', True),
    ('word boundary', '\\bfoo', False, b'xfoo', False),
    ('word boundary', '\\bfoo', False, b' foo', True),
    ('word boundary', 'foo\\b', False, b'foo', True),
    ('word boundary', 'foo\\b', False, b'foox', False),
    ('word boundary', 'foo\\b', False, b'foo ', True),
    ('word boundary', '\\b', False, b'a', True),
    ('word boundary', '\\b', False, b' ', False),
    ('word boundary', '\\b', False, b'', False),
    ('word boundary', '\\b', False, b'  ', False),
    ('word boundary', '\\b', False, b'a b', True),
    ('word boundary', '\\B', False, b'a', False),
    ('word boundary', '\\B', False, b'aa', True),
    ('word boundary', '\\B', False, b'a a', False),
    ('word boundary', '\\B', False, b' ', True),
    ('word boundary', '\\B', False, b'  ', True),
    ('word boundary', '\\B', False, b'a ', True),
    ('word boundary', 'a\\Bb', False, b'ab', True),
    ('word boundary', 'a\\Bb', False, b'a b', False),
    ('word boundary', '\\<foo', False, b'foo', True),
    ('word boundary', '\\<foo', False, b'xfoo', False),
    ('word boundary', '\\<foo', False, b' foo', True),
    ('word boundary', 'foo\\>', False, b'foo', True),
    ('word boundary', 'foo\\>', False, b'foox', False),
    ('word boundary', 'foo\\>', False, b'foo ', True),
    ('word boundary', '\\<foo\\>', False, b'foo', True),
    ('word boundary', '\\<foo\\>', False, b'a foo b', True),
    ('word boundary', '\\<foo\\>', False, b'foobar', False),
    ('word boundary', '\\<foo\\>', False, b'foo-bar', True),
    ('word boundary', '\\bexec\\s*\\(', False, b'exec(', True),
    ('word boundary', '\\bexec\\s*\\(', False, b'exec (', True),
    ('word boundary', '\\bexec\\s*\\(', False, b'xexec(', False),
    ('word boundary', '\\bexec\\s*\\(', False, b'_exec(', False),
    ('word boundary', '\\bexec\\s*\\(', False, b'exec', False),
    ('lazy-looking', 'a+?', False, b'a', True),
    ('lazy-looking', 'a+?', False, b'', False),
    ('lazy-looking', 'a+?', False, b'b', True),
    ('lazy-looking', 'a+?', False, b'ab', True),
    ('lazy-looking', '^a+?$', False, b'a', True),
    ('lazy-looking', '^a+?$', False, b'aa', True),
    ('lazy-looking', '^a+?$', False, b'', False),
    ('lazy-looking', '^a+?$', False, b'aaa', True),
    ('lazy-looking', '^a*?$', False, b'a', True),
    ('lazy-looking', '^a*?$', False, b'aa', True),
    ('lazy-looking', '^a*?$', False, b'', False),
    ('lazy-looking', '^a*?$', False, b'b', False),
    ('lazy-looking', '^a??$', False, b'a', True),
    ('lazy-looking', '^a??$', False, b'aa', False),
    ('lazy-looking', '^a??$', False, b'', False),
    ('lazy-looking', '^a??$', False, b'b', False),
    ('lazy-looking', '^a*+$', False, b'a', True),
    ('lazy-looking', '^a*+$', False, b'aa', True),
    ('lazy-looking', '^a*+$', False, b'', False),
    ('lazy-looking', '^a*+$', False, b'b', False),
    ('lazy-looking', '^a++$', False, b'a', True),
    ('lazy-looking', '^a++$', False, b'aa', True),
    ('lazy-looking', '^a++$', False, b'', False),
    ('lazy-looking', '^a++$', False, b'b', False),
    ('lazy-looking', '^a?+$', False, b'a', True),
    ('lazy-looking', '^a?+$', False, b'aa', True),
    ('lazy-looking', '^a?+$', False, b'', False),
    ('lazy-looking', '^a?+$', False, b'b', False),
    ('lazy-looking', '^(a+)+$', False, b'a', True),
    ('lazy-looking', '^(a+)+$', False, b'aa', True),
    ('lazy-looking', '^(a+)+$', False, b'aaa', True),
    ('lazy-looking', '^(a+)+$', False, b'aab', False),
    ('lazy-looking', '^(a+)+$', False, b'', False),
    ('lazy-looking', '^(a*)*$', False, b'a', True),
    ('lazy-looking', '^(a*)*$', False, b'aa', True),
    ('lazy-looking', '^(a*)*$', False, b'aab', False),
    ('lazy-looking', '^(a*)*$', False, b'', False),
    ('lazy-looking', '^(a|aa)+$', False, b'a', True),
    ('lazy-looking', '^(a|aa)+$', False, b'aa', True),
    ('lazy-looking', '^(a|aa)+$', False, b'aaa', True),
    ('lazy-looking', '^(a|aa)+$', False, b'aaab', False),
    ('lazy-looking', '^a{2}*$', False, b'', False),
    ('lazy-looking', '^a{2}*$', False, b'a', False),
    ('lazy-looking', '^a{2}*$', False, b'aa', True),
    ('lazy-looking', '^a{2}*$', False, b'aaa', False),
    ('lazy-looking', '^a{2}*$', False, b'aaaa', True),
    ('lazy-looking', '^a{2}+$', False, b'', False),
    ('lazy-looking', '^a{2}+$', False, b'a', False),
    ('lazy-looking', '^a{2}+$', False, b'aa', True),
    ('lazy-looking', '^a{2}+$', False, b'aaa', False),
    ('lazy-looking', '^a{2}+$', False, b'aaaa', True),
    ('lazy-looking', '^a{2}{3}$', False, b'aaaaaa', True),
    ('lazy-looking', '^a{2}{3}$', False, b'aaaaa', False),
    ('lazy-looking', '^a{2}{3}$', False, b'aaaa', False),
    ('lazy-looking', '^(ab)*c?$', False, b'', False),
    ('lazy-looking', '^(ab)*c?$', False, b'ab', True),
    ('lazy-looking', '^(ab)*c?$', False, b'abab', True),
    ('lazy-looking', '^(ab)*c?$', False, b'c', True),
    ('lazy-looking', '^(ab)*c?$', False, b'abc', True),
    ('lazy-looking', '^(ab)*c?$', False, b'ababc', True),
    ('lazy-looking', '^(ab)*c?$', False, b'abc c', False),
    ('interval', 'a{', False, b'a{', True),
    ('interval', 'a{', False, b'a', False),
    ('interval', 'a{', False, b'a{{', True),
    ('interval', 'a{,', False, b'a{,', True),
    ('interval', 'a{,', False, b'a', False),
    ('interval', 'a{1', False, b'a{1', True),
    ('interval', 'a{1', False, b'a', False),
    ('interval', 'a{1', False, b'a1', False),
    ('interval', 'a{1,2', False, b'a{1,2', True),
    ('interval', 'a{1,2', False, b'aa', False),
    ('interval', 'a{x}', False, b'a{x}', True),
    ('interval', 'a{x}', False, b'a', False),
    ('interval', 'a{x}', False, b'ax', False),
    ('interval', 'a{ 1}', False, b'a{ 1}', True),
    ('interval', 'a{ 1}', False, b'a', False),
    ('interval', '^a{2}$', False, b'a', False),
    ('interval', '^a{2}$', False, b'aa', True),
    ('interval', '^a{2}$', False, b'aaa', False),
    ('interval', '^a{2,}$', False, b'a', False),
    ('interval', '^a{2,}$', False, b'aa', True),
    ('interval', '^a{2,}$', False, b'aaa', True),
    ('interval', '^a{2,}$', False, b'aaaa', True),
    ('interval', '^a{,2}$', False, b'', False),
    ('interval', '^a{,2}$', False, b'a', True),
    ('interval', '^a{,2}$', False, b'aa', True),
    ('interval', '^a{,2}$', False, b'aaa', False),
    ('interval', '^a{,}$', False, b'', False),
    ('interval', '^a{,}$', False, b'a', True),
    ('interval', '^a{,}$', False, b'aaa', True),
    ('interval', '^a{0}b$', False, b'b', True),
    ('interval', '^a{0}b$', False, b'ab', False),
    ('interval', '^a{1,3}$', False, b'', False),
    ('interval', '^a{1,3}$', False, b'a', True),
    ('interval', '^a{1,3}$', False, b'aaa', True),
    ('interval', '^a{1,3}$', False, b'aaaa', False),
    ('interval', '^a{01}$', False, b'a', True),
    ('interval', '^a{01}$', False, b'aa', False),
    ('interval', '^(ab){2}$', False, b'abab', True),
    ('interval', '^(ab){2}$', False, b'ab', False),
    ('interval', '^(ab){2}$', False, b'ababab', False),
    ('interval', '^[0-9]{3}-[0-9]{4}$', False, b'555-1234', True),
    ('interval', '^[0-9]{3}-[0-9]{4}$', False, b'55-1234', False),
    ('interval', '^[0-9]{3}-[0-9]{4}$', False, b'5555-1234', False),
    ('interval', '^.{3}$', False, b'abc', True),
    ('interval', '^.{3}$', False, b'ab', False),
    ('interval', '^.{3}$', False, b'abcd', False),
    ('interval', 'x{32767}', False, b'x', False),
    ('interval', 'x{32767}', False, b'xx', False),
    ('literal brace', '\\{', False, b'{', True),
    ('literal brace', '\\{', False, b'a', False),
    ('literal brace', 'a\\{2\\}', False, b'a{2}', True),
    ('literal brace', 'a\\{2\\}', False, b'aa', False),
    ('literal brace', '\\$\\{', False, b'${', True),
    ('literal brace', '\\$\\{', False, b'$', False),
    ('literal brace', '^\\{\\{[^}]*\\}\\}', False, b'{{ x }}', True),
    ('literal brace', '^\\{\\{[^}]*\\}\\}', False, b'{{ x }', False),
    ('literal brace', '^\\{\\{[^}]*\\}\\}', False, b'{ x }', False),
    ('alternation', '^(a|)b$', False, b'b', True),
    ('alternation', '^(a|)b$', False, b'ab', True),
    ('alternation', '^(a|)b$', False, b'cb', False),
    ('alternation', '^(|a)b$', False, b'b', True),
    ('alternation', '^(|a)b$', False, b'ab', True),
    ('alternation', '^a|b$', False, b'ax', True),
    ('alternation', '^a|b$', False, b'xb', True),
    ('alternation', '^a|b$', False, b'xx', False),
    ('alternation', '^a|b$', False, b'a', True),
    ('alternation', '^a|b$', False, b'b', True),
    ('alternation', '^(a|b|)$', False, b'', False),
    ('alternation', '^(a|b|)$', False, b'a', True),
    ('alternation', '^(a|b|)$', False, b'b', True),
    ('alternation', '^(a|b|)$', False, b'c', False),
    ('alternation', 'a||b', False, b'x', True),
    ('alternation', 'a||b', False, b'', False),
    ('alternation', 'a||b', False, b'a', True),
    ('alternation', 'a|', False, b'x', True),
    ('alternation', 'a|', False, b'', False),
    ('alternation', '|a', False, b'x', True),
    ('alternation', '|a', False, b'', False),
    ('alternation', '()', False, b'x', True),
    ('alternation', '()', False, b'', False),
    ('alternation', '^(foo|foobar)$', False, b'foo', True),
    ('alternation', '^(foo|foobar)$', False, b'foobar', True),
    ('alternation', '^(foo|foobar)$', False, b'foob', False),
    ('alternation', '^(a|ab)(c|bcd)(d*)$', False, b'abcd', True),
    ('alternation', '^(a|ab)(c|bcd)(d*)$', False, b'abc', True),
    ('alternation', '^(a|ab)(c|bcd)(d*)$', False, b'ad', False),
    ('alternation', '^(a|ab)(c|bcd)(d*)$', False, b'abcdd', True),
    ('alternation', '^(x|xy)*z$', False, b'xyz', True),
    ('alternation', '^(x|xy)*z$', False, b'xz', True),
    ('alternation', '^(x|xy)*z$', False, b'xyxz', True),
    ('alternation', '^(x|xy)*z$', False, b'xyxyz', True),
    ('alternation', '^(x|xy)*z$', False, b'xxz', True),
    ('alternation', '^(x|xy)*z$', False, b'xyyz', False),
    ('anchors', 'a^b', False, b'a^b', False),
    ('anchors', 'a^b', False, b'ab', False),
    ('anchors', 'a^b', False, b'a', False),
    ('anchors', 'a$b', False, b'a$b', False),
    ('anchors', 'a$b', False, b'ab', False),
    ('anchors', '^^a', False, b'a', True),
    ('anchors', '^^a', False, b'^a', False),
    ('anchors', 'a$$', False, b'a', True),
    ('anchors', 'a$$', False, b'a$', False),
    ('anchors', '(^a|b)', False, b'a', True),
    ('anchors', '(^a|b)', False, b'ba', True),
    ('anchors', '(^a|b)', False, b'xa', False),
    ('anchors', '(^a|b)', False, b'b', True),
    ('anchors', '(^a|b)', False, b'xb', True),
    ('anchors', '(^a|b)', False, b'x', False),
    ('anchors', '(a|^)b', False, b'b', True),
    ('anchors', '(a|^)b', False, b'ab', True),
    ('anchors', '(a|^)b', False, b'xb', False),
    ('anchors', '(a|^)b', False, b'xab', True),
    ('anchors', 'x*^a', False, b'a', True),
    ('anchors', 'x*^a', False, b'xa', False),
    ('anchors', 'x*^a', False, b'ba', False),
    ('anchors', '^$', False, b'', False),
    ('anchors', '^$', False, b'a', False),
    ('anchors', '^$', False, b'\n', True),
    ('anchors', '^', False, b'', False),
    ('anchors', '^', False, b'a', True),
    ('anchors', '^', False, b'\n', True),
    ('anchors', '$', False, b'', False),
    ('anchors', '$', False, b'a', True),
    ('anchors', '$', False, b'\n', True),
    ('anchors', '^*a', False, b'a', True),
    ('anchors', '^*a', False, b'*a', True),
    ('anchors', '^*a', False, b'ba', True),
    ('anchors', '^+a', False, b'a', True),
    ('anchors', '^+a', False, b'*a', False),
    ('anchors', '^+a', False, b'ba', False),
    ('anchors', 'a$*', False, b'a', True),
    ('anchors', 'a$*', False, b'b', False),
    ('anchors', '\\^a', False, b'^a', True),
    ('anchors', '\\^a', False, b'a', False),
    ('anchors', 'a\\$', False, b'a$', True),
    ('anchors', 'a\\$', False, b'a', False),
    ('anchors', '\\`a', False, b'a', True),
    ('anchors', '\\`a', False, b'ba', False),
    ('anchors', "a\\'", False, b'a', True),
    ('anchors', "a\\'", False, b'ab', False),
    ('leading operators', '*a', False, b'a', True),
    ('leading operators', '*a', False, b'*a', True),
    ('leading operators', '*a', False, b'b', False),
    ('leading operators', '+a', False, b'a', True),
    ('leading operators', '+a', False, b'+a', True),
    ('leading operators', '+a', False, b'b', False),
    ('leading operators', '?a', False, b'a', True),
    ('leading operators', '?a', False, b'?a', True),
    ('leading operators', '?a', False, b'b', False),
    ('leading operators', '(*a)', False, b'a', True),
    ('leading operators', '(*a)', False, b'*a', True),
    ('leading operators', '(*a)', False, b'b', False),
    ('leading operators', 'a|*b', False, b'a', True),
    ('leading operators', 'a|*b', False, b'b', True),
    ('leading operators', 'a|*b', False, b'*b', True),
    ('leading operators', 'a|*b', False, b'c', False),
    ('leading operators', '^*', False, b'', False),
    ('leading operators', '^*', False, b'a', True),
    ('parens', 'a)', False, b'a)', True),
    ('parens', 'a)', False, b'a', False),
    ('parens', ')', False, b')', True),
    ('parens', ')', False, b'a', False),
    ('parens', '(a))', False, b'a)', True),
    ('parens', '(a))', False, b'a', False),
    ('parens', '\\(a\\)', False, b'(a)', True),
    ('parens', '\\(a\\)', False, b'a', False),
    ('parens', '(a)(b)?c', False, b'ac', True),
    ('parens', '(a)(b)?c', False, b'abc', True),
    ('parens', '(a)(b)?c', False, b'bc', False),
    ('backref', '(a)\\1', False, b'aa', True),
    ('backref', '(a)\\1', False, b'a', False),
    ('backref', '(a)\\1', False, b'ab', False),
    ('backref', '(a|b)\\1', False, b'aa', True),
    ('backref', '(a|b)\\1', False, b'bb', True),
    ('backref', '(a|b)\\1', False, b'ab', False),
    ('backref', '(a|b)\\1', False, b'ba', False),
    ('backref', '(a|b)\\1', True, b'aa', True),
    ('backref', '(a|b)\\1', True, b'AA', True),
    ('backref', '(a|b)\\1', True, b'aA', True),
    ('backref', '(a|b)\\1', True, b'ab', False),
    ('backref', '([A-Za-z0-9])\\1{9,}', False, b'aaaaaaaaaa', True),
    ('backref', '([A-Za-z0-9])\\1{9,}', False, b'aaaaaaaaa', False),
    ('backref', '([A-Za-z0-9])\\1{9,}', False, b'abababababab', False),
    ('backref', '([A-Za-z0-9])\\1{9,}', False, b'0000000000', True),
    ('backref', '([a-z]+) \\1', False, b'foo foo', True),
    ('backref', '([a-z]+) \\1', False, b'foo bar', False),
    ('backref', '([a-z]+) \\1', False, b'a a', True),
    ('backref', '([a-z]+) \\1', False, b'ab b', True),
    ('backref', '(a)\\10', False, b'aa0', True),
    ('backref', '(a)\\10', False, b'aa', False),
    ('backref', '(a)\\10', False, b'a0', False),
    ('backref', '^(.)(.).?\\2\\1$', False, b'abba', True),
    ('backref', '^(.)(.).?\\2\\1$', False, b'abcba', True),
    ('backref', '^(.)(.).?\\2\\1$', False, b'abab', False),
    ('backref', '^(.)(.).?\\2\\1$', False, b'aa', False),
    ('dot', 'a.c', False, b'abc', True),
    ('dot', 'a.c', False, b'a\tc', True),
    ('dot', 'a.c', False, b'a c', True),
    ('dot', 'a.c', False, b'ac', False),
    ('dot', 'a.c', False, b'a\xffc', True),
    ('dot', 'a.c', False, b'a\x01c', True),
    ('dot', 'a.c', False, b'a\x7fc', True),
    ('dot', 'a.*c', False, b'ac', True),
    ('dot', 'a.*c', False, b'abc', True),
    ('dot', 'a.*c', False, b'a c d', True),
    ('dot', 'a.*c', False, b'a', False),
    ('dot', 'a.*c', False, b'abd', False),
    ('dot', '^.*$', False, b'', False),
    ('dot', '^.*$', False, b'abc', True),
    ('dot', 'a\\.c', False, b'a.c', True),
    ('dot', 'a\\.c', False, b'abc', False),
    ('newline', '"[^"]*"', False, b'"a"', True),
    ('newline', '"[^"]*"', False, b'"a', False),
    ('newline', '"[^"]*"', False, b'a"', False),
    ('newline', '"[^"]*"', False, b'"a\nb"', False),
    ('newline', '"[^"]*"', False, b'"a\n"', False),
    ('newline', '"[^"]*"', False, b'""', True),
    ('newline', 'a[^b]c', False, b'a\nc', False),
    ('newline', 'a[^b]c', False, b'axc', True),
    ('newline', 'a[^b]c', False, b'abc', False),
    ('newline', 'a.c', False, b'a\nc', False),
    ('newline', 'a.c', False, b'abc', True),
    ('newline', 'a\\sc', False, b'a\nc', False),
    ('newline', 'a\\sc', False, b'a c', True),
    ('newline', 'a\\Wc', False, b'a\nc', False),
    ('newline', 'a\\Wc', False, b'a-c', True),
    ('newline', 'a[[:space:]]c', False, b'a\nc', False),
    ('newline', 'a[[:space:]]c', False, b'a c', True),
    ('newline', 'a[[:cntrl:]]c', False, b'a\nc', False),
    ('newline', 'a[[:cntrl:]]c', False, b'a\x01c', True),
    ('newline', 'x[^y]*$', False, b'xab\ncd', True),
    ('newline', 'x[^y]*$', False, b'x\ncd', True),
    ('newline', 'x[^y]*$', False, b'xab', True),
    ('newline', '^[^"]*"[^"]*$', False, b'a"b', True),
    ('newline', '^[^"]*"[^"]*$', False, b'a\n"b', True),
    ('newline', '^[^"]*"[^"]*$', False, b'a"\nb', True),
    ('newline', '^[^"]*"[^"]*$', False, b'"', True),
    ('newline', '(a|b)\\s*(c|d)', False, b'a\nc', False),
    ('newline', '(a|b)\\s*(c|d)', False, b'a c', True),
    ('newline', '(a|b)\\s*(c|d)', False, b'a  d', True),
    ('newline', 'a\\s*$', False, b'a  \nb', True),
    ('newline', 'a\\s*$', False, b'a \n', True),
    ('newline', 'a\\s*$', False, b'a', True),
    ('newline', '^\\s*$', False, b'\n', True),
    ('newline', '^\\s*$', False, b'  \n', True),
    ('newline', '^\\s*$', False, b'a\n   \nb', True),
    ('newline', '^\\s*$', False, b'a\nb', False),
    ('newline', '\\s+$', False, b'a \nb', True),
    ('newline', '\\s+$', False, b'a\nb', False),
    ('newline', '\\s+$', False, b'a  ', True),
    ('ignore case', 'abc', True, b'abc', True),
    ('ignore case', 'abc', True, b'ABC', True),
    ('ignore case', 'abc', True, b'aBc', True),
    ('ignore case', 'abc', True, b'abd', False),
    ('ignore case', '[a-c]+', True, b'ABC', True),
    ('ignore case', '[a-c]+', True, b'xyz', False),
    ('ignore case', '[a-c]+', True, b'AbC', True),
    ('ignore case', '[^a-c]', True, b'A', False),
    ('ignore case', '[^a-c]', True, b'a', False),
    ('ignore case', '[^a-c]', True, b'd', True),
    ('ignore case', '[^a-c]', True, b'D', True),
    ('ignore case', '[^a-c]', True, b'abc', False),
    ('ignore case', '[^a-c]', True, b'ABC', False),
    ('ignore case', '[^A-C]', True, b'a', False),
    ('ignore case', '[^A-C]', True, b'A', False),
    ('ignore case', '[^A-C]', True, b'd', True),
    ('ignore case', '[A-Z]', True, b'a', True),
    ('ignore case', '[A-Z]', True, b'z', True),
    ('ignore case', '[A-Z]', True, b'1', False),
    ('ignore case', '[A-Z]', False, b'a', False),
    ('ignore case', '[A-Z]', False, b'z', False),
    ('ignore case', '[A-Z]', False, b'1', False),
    ('ignore case', 'password\\s*=', True, b'PASSWORD =', True),
    ('ignore case', 'password\\s*=', True, b'Password=', True),
    ('ignore case', 'password\\s*=', True, b'passwd =', False),
    ('ignore case', '\\w+', True, b'\xc9', False),
    ('ignore case', '\\w+', True, b'\xe9', False),
    ('ignore case', '\\w+', True, b'x', True),
    ('ignore case', 'caf.', True, b'CAF\xc3\x89', True),
    ('ignore case', 'k', True, b'K', True),
    ('ignore case', 'k', True, b'\xe2\x84\xaa', False),
    ('ignore case', '(ab)\\1', True, b'abab', True),
    ('ignore case', '(ab)\\1', True, b'ABab', True),
    ('ignore case', '(ab)\\1', True, b'abAB', True),
    ('ignore case', '(ab)\\1', True, b'abba', False),
    ('ignore case', '\\bIEX\\b', True, b'iex', True),
    ('ignore case', '\\bIEX\\b', True, b'IeX', True),
    ('ignore case', '\\bIEX\\b', True, b'siex', False),
    ('empty', '', False, b'', False),
    ('empty', '', False, b'a', True),
    ('empty', '', False, b'\n', True),
    ('empty', 'x*', False, b'', False),
    ('empty', 'x*', False, b'a', True),
    ('empty', 'x*', False, b'\n', True),
    ('empty', 'x', False, b'', False),
    ('empty', 'x', False, b'\n', False),
    ('trailing newline', 'a$', False, b'a', True),
    ('trailing newline', 'a$', False, b'a\n', True),
    ('trailing newline', 'a$', False, b'a\nb', True),
    ('trailing newline', 'a$', False, b'b\na', True),
    ('trailing newline', 'a$', False, b'b\na\n', True),
    ('trailing newline', '^a', False, b'a\n', True),
    ('trailing newline', '^a', False, b'b\na\n', True),
    ('trailing newline', '^a', False, b'b\nca', False),
    ('trailing newline', 'b$', False, b'a\nb', True),
    ('trailing newline', 'b$', False, b'a\nb\n', True),
    ('trailing newline', 'b$', False, b'ab\n', True),
    ('trailing newline', '^b', False, b'a\nb', True),
    ('trailing newline', '^b', False, b'a\n\nb', True),
    ('trailing newline', '^b', False, b'ab', False),
    ('crlf', 'a$', False, b'a\r\n', False),
    ('crlf', 'a$', False, b'a\r', False),
    ('crlf', 'a$', False, b'a', True),
    ('crlf', 'a\\r$', False, b'a\r\n', False),
    ('crlf', 'a\\r$', False, b'a\r', False),
    ('crlf', 'a[[:space:]]*$', False, b'a\r\n', True),
    ('crlf', 'a[[:space:]]*$', False, b'a \r\n', True),
    ('crlf', 'a.$', False, b'a\r\n', True),
    ('crlf', 'a.$', False, b'a\n', False),
    ('real pattern', '(password|passwd|pwd|secret|api_key|apikey|auth_token|access_token)\\s*[=:]\\s*["\\x27][^${"\\x27[:space:]]{4,}', False, b'password = "hunter2"', True),
    ('real pattern', '(password|passwd|pwd|secret|api_key|apikey|auth_token|access_token)\\s*[=:]\\s*["\\x27][^${"\\x27[:space:]]{4,}', False, b"secret: 'abcd'", False),
    ('real pattern', '(password|passwd|pwd|secret|api_key|apikey|auth_token|access_token)\\s*[=:]\\s*["\\x27][^${"\\x27[:space:]]{4,}', False, b'password = "ab"', False),
    ('real pattern', '(password|passwd|pwd|secret|api_key|apikey|auth_token|access_token)\\s*[=:]\\s*["\\x27][^${"\\x27[:space:]]{4,}', False, b'password = "${X}"', False),
    ('real pattern', '(password|passwd|pwd|secret|api_key|apikey|auth_token|access_token)\\s*[=:]\\s*["\\x27][^${"\\x27[:space:]]{4,}', False, b'pwd="sup3rs3cret"', True),
    ('real pattern', '(password|passwd|pwd|secret|api_key|apikey|auth_token|access_token)\\s*[=:]\\s*["\\x27][^${"\\x27[:space:]]{4,}', False, b'password = "a b c d"', False),
    ('real pattern', '(execute|executemany)[[:space:]]*\\([[:space:]]*(f["\\x27]|("[^"]*"|\\x27[^\\x27]*\\x27)[[:space:]]*(\\+|%|\\.format\\())', False, b'execute(f"x")', True),
    ('real pattern', '(execute|executemany)[[:space:]]*\\([[:space:]]*(f["\\x27]|("[^"]*"|\\x27[^\\x27]*\\x27)[[:space:]]*(\\+|%|\\.format\\())', False, b'execute("a" + b)', True),
    ('real pattern', '(execute|executemany)[[:space:]]*\\([[:space:]]*(f["\\x27]|("[^"]*"|\\x27[^\\x27]*\\x27)[[:space:]]*(\\+|%|\\.format\\())', False, b'execute("a %s" % b)', True),
    ('real pattern', '(execute|executemany)[[:space:]]*\\([[:space:]]*(f["\\x27]|("[^"]*"|\\x27[^\\x27]*\\x27)[[:space:]]*(\\+|%|\\.format\\())', False, b'execute("a".format(b))', True),
    ('real pattern', '(execute|executemany)[[:space:]]*\\([[:space:]]*(f["\\x27]|("[^"]*"|\\x27[^\\x27]*\\x27)[[:space:]]*(\\+|%|\\.format\\())', False, b'execute("a", b)', False),
    ('real pattern', '(execute|executemany)[[:space:]]*\\([[:space:]]*(f["\\x27]|("[^"]*"|\\x27[^\\x27]*\\x27)[[:space:]]*(\\+|%|\\.format\\())', False, b"executemany ( f'x' )", False),
    ('real pattern', 'curl\\s+.*\\|\\s*(bash|sh)|wget\\s+.*\\|\\s*(bash|sh)', False, b'curl http://x | bash', True),
    ('real pattern', 'curl\\s+.*\\|\\s*(bash|sh)|wget\\s+.*\\|\\s*(bash|sh)', False, b'curl x | sh', True),
    ('real pattern', 'curl\\s+.*\\|\\s*(bash|sh)|wget\\s+.*\\|\\s*(bash|sh)', False, b'wget -O- x |sh', True),
    ('real pattern', 'curl\\s+.*\\|\\s*(bash|sh)|wget\\s+.*\\|\\s*(bash|sh)', False, b'curl x', False),
    ('real pattern', 'curl\\s+.*\\|\\s*(bash|sh)|wget\\s+.*\\|\\s*(bash|sh)', False, b'curl x | shred', True),
    ('real pattern', '\\b(eval|exec)\\s*\\(', False, b'eval(x)', True),
    ('real pattern', '\\b(eval|exec)\\s*\\(', False, b'exec (x)', True),
    ('real pattern', '\\b(eval|exec)\\s*\\(', False, b'evaluate(x)', False),
    ('real pattern', '\\b(eval|exec)\\s*\\(', False, b'x.eval(y)', True),
    ('real pattern', '\\b(eval|exec)\\s*\\(', False, b'_eval(x)', False),
    ('real pattern', '-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----', False, b'-----BEGIN RSA PRIVATE KEY-----', True),
    ('real pattern', '-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----', False, b'-----BEGIN PRIVATE KEY-----', True),
    ('real pattern', '-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----', False, b'-----BEGIN CERTIFICATE-----', False),
    ('real pattern', '-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----', False, b'-----BEGIN PGP PRIVATE KEY BLOCK-----', True),
    ('real pattern', '(%2e%2e|%252e%252e|\\.\\.%2f|\\.\\.%5c|%2f\\.\\.|%5c\\.\\.)', True, b'%2E%2e', True),
    ('real pattern', '(%2e%2e|%252e%252e|\\.\\.%2f|\\.\\.%5c|%2f\\.\\.|%5c\\.\\.)', True, b'..%2F', True),
    ('real pattern', '(%2e%2e|%252e%252e|\\.\\.%2f|\\.\\.%5c|%2f\\.\\.|%5c\\.\\.)', True, b'a/..%5C', True),
    ('real pattern', '(%2e%2e|%252e%252e|\\.\\.%2f|\\.\\.%5c|%2f\\.\\.|%5c\\.\\.)', True, b'../', False),
    ('real pattern', '(%2e%2e|%252e%252e|\\.\\.%2f|\\.\\.%5c|%2f\\.\\.|%5c\\.\\.)', True, b'%252E%252e', True),
    ('real pattern', '^(application/x-executable|application/x-sharedlib)', False, b'application/x-executable', True),
    ('real pattern', '^(application/x-executable|application/x-sharedlib)', False, b'text/x', False),
    ('real pattern', '^(application/x-executable|application/x-sharedlib)', False, b'application/x-sharedlib; charset=binary', True),
    ('real pattern', '^(application/x-executable|application/x-sharedlib)', False, b'xapplication/x-executable', False),
]

# patterns grep -E rejects (exit status 2): the bash helper reads that as "no match" for ever, rx raises instead
INVALID = [
    "(", "(a", "(()", "((a)", "a|(", "a{2,1}", "a{}", "a{1,2,3}", "a{65536}", "x{2,1}y", "[", "[a", "[]", "[^]", "[a-",
    "[z-a]", "[a-c-e]", "[a-z-9]", "[[:foo:]]", "[[:alpha:]", "[[:alpha]]", "[:alpha:]", "[:digit:]", "[[:alpha:]-z]",
    "[a-[:alpha:]]", "[[:^alpha:]]", "[[.hyphen.]]", "\\", "a\\", "\\1", "\\9", "(a)\\2", "(a\\1)", "(a)|\\1",
]


class RecordedTable(unittest.TestCase):
    def test_table(self):
        for group, pat, ci, data, want in CASES:
            with self.subTest(group=group, pattern=pat, ci=ci, data=data):
                got = rx.search_lines(rx.ere_to_py(pat, ci), data)
                self.assertEqual(got, want, f"{pat!r} on {data!r}: grep says {want}, rx says {got}")

    def test_table_without_simplification(self):
        # the flattened nested repetitions must mean exactly what the literal translation means
        for group, pat, ci, data, want in CASES:
            with self.subTest(group=group, pattern=pat, ci=ci, data=data):
                self.assertEqual(rx.search_lines(rx.ere_to_py(pat, ci, simplify=False), data), want)

    def test_per_line_path_agrees_with_whole_buffer_path(self):
        for group, pat, ci, data, want in CASES:
            c = rx.ere_to_py(pat, ci)
            lines = data.split(b"\n")
            if data.endswith(b"\n"):
                lines = lines[:-1]
            per_line = any(c.search(x) for x in lines) if data else False
            with self.subTest(pattern=pat, data=data):
                self.assertEqual(per_line, rx.search_lines(c, data))


@unittest.skipUnless(live_grep_available(), "GNU grep not available")
class LiveGrep(unittest.TestCase):
    """The recorded table is only worth anything if it is what grep does today."""

    def test_table_is_what_grep_says(self):
        for group, pat, ci, data, want in CASES:
            with self.subTest(group=group, pattern=pat, ci=ci, data=data):
                self.assertEqual(grep_q(pat, data, ci) == 0, want)

    def test_invalid_patterns_are_rejected_by_grep(self):
        for pat in INVALID:
            with self.subTest(pattern=pat):
                self.assertEqual(grep_q(pat, b"x\n"), 2)

    def test_range_order_is_checked_after_upper_casing_under_i(self):
        # glibc upper-cases a case-insensitive pattern before it orders a range
        self.assertEqual(grep_q("[Z-a]x", b"x\n", ci=False), 1)
        self.assertEqual(grep_q("[Z-a]x", b"x\n", ci=True), 2)


class Syntax(unittest.TestCase):
    def test_invalid_patterns_raise(self):
        for pat in INVALID:
            with self.subTest(pattern=pat):
                with self.assertRaises(rx.EREError):
                    rx.ere_to_py(pat)

    def test_range_order_under_ignore_case(self):
        rx.ere_to_py("[Z-a]x", False)
        with self.assertRaises(rx.EREError):
            rx.ere_to_py("[Z-a]x", True)

    def test_unsupported_is_loud_not_silent(self):
        for pat in ("[[.a.]]", "[[=a=]b]", "{1}a", "^{2}", "(^){2}x\\1", "a|{2}"):
            with self.subTest(pattern=pat):
                if pat in ("(^){2}x\\1",):
                    continue
                with self.assertRaises(rx.UnsupportedERE):
                    rx.ere_to_py(pat)

    def test_repeated_anchor_with_backreference_is_unsupported(self):
        with self.assertRaises(rx.UnsupportedERE):
            rx.ere_to_py("^*(a)\\1")

    def test_newline_separates_patterns(self):
        c = rx.ere_to_py("foo\nbar")
        self.assertTrue(rx.search_lines(c, b"xbar\n"))
        self.assertTrue(rx.search_lines(c, b"foo\n"))
        self.assertFalse(rx.search_lines(c, b"baz\n"))

    def test_str_with_non_ascii_is_matched_as_utf8_bytes(self):
        c = rx.ere_to_py("café")
        self.assertTrue(rx.search_lines(c, "un café\n".encode()))
        self.assertFalse(rx.search_lines(c, b"un cafe\n"))

    def test_warnings_for_leading_operators(self):
        self.assertTrue(rx.parse_ere("*a").warnings)
        self.assertFalse(rx.parse_ere("ab*").warnings)


class Hazards(unittest.TestCase):
    """Patterns that parse and match, but do not mean what they were probably written to mean."""

    @staticmethod
    def w(pat: str, ci: bool = False) -> str:
        return " | ".join(rx.parse_ere(pat, ci).warnings)

    def test_stray_backslash_escape(self):
        self.assertIn("stray backslash before 'd'", self.w(r"\d+"))
        self.assertIn("stray backslash before 'x'", self.w(r"\x41"))
        self.assertEqual(self.w(r"\.\w\s\/\-\&"), "")

    def test_backslash_inside_a_bracket_expression(self):
        self.assertIn("ordinary member", self.w(r'[^"\s]+'))
        self.assertIn("does not escape", self.w(r"[\]]"))
        self.assertEqual(self.w(r"[\\]"), "")
        self.assertEqual(self.w(r"[[:space:]]"), "")

    def test_repetition_of_a_repetition_and_literal_brace(self):
        self.assertIn("not lazy", self.w("a+?"))
        self.assertIn("literal brace", self.w("a{x}"))

    def test_empty_alternative_matches_every_line(self):
        for pat in ("a|", "(|a)", "a*", "x?"):
            with self.subTest(pattern=pat):
                self.assertIn("matches every line", self.w(pat))
        self.assertEqual(self.w("(a|b)c"), "")

    def test_word_boundary_next_to_a_non_word_character(self):
        self.assertIn("in front of '%'", self.w(r"\b(system|%x\{)"))
        self.assertIn("after a character that cannot be a word character", self.w(r"\b(rand\(\)|mt_rand)\b"))
        self.assertEqual(self.w(r"\bfoo\b"), "")
        self.assertEqual(self.w(r"\b(requests\.get)\s*\([^)]*\b(url|host)\b"), "")
        self.assertEqual(self.w(r"x\)\bfoo"), "")

    @unittest.skipUnless(live_grep_available(), "GNU grep not available")
    def test_the_boundary_hazard_is_real(self):
        # the rule from scan_universal_patterns: written to catch rand(), it misses the call in ordinary code
        pat = r"\b(Math\.random|random\.random|rand\(\)|mt_rand)\b"
        self.assertEqual(grep_q(pat, b"int x = rand();\n"), 1)
        self.assertEqual(grep_q(pat, b"x = Math.random();\n"), 0)
        self.assertFalse(rx.search_lines(rx.ere_to_py(pat), b"int x = rand();\n"))
        # ... and the Ruby rule misses a backtick command after a space
        ruby = r"\b(system|exec|Kernel\.exec|%x\{|`[^`]+`)"
        self.assertEqual(grep_q(ruby, b"out = `ls`\n"), 1)
        self.assertEqual(grep_q(ruby, b"p`ls`\n"), 0)


class NoLazyOperators(unittest.TestCase):
    """+? *? ?? are repetitions of a repetition in ERE, never lazy or possessive."""

    def test_emitted_source_has_no_lazy_or_possessive_quantifier(self):
        for pat in ("a+?", "a*?", "a??", "a*+", "a++", "a?+", "(a+)?", "a{2}*", "a{2}+", "a{2,3}?", "[ab]+?c"):
            src = rx.ere_to_py_source(pat, simplify=False)
            with self.subTest(pattern=pat):
                self.assertNotRegex(src, rb"[*+?}]\?|[*+?}]\+", "Python would read this as lazy or possessive")

    def test_lazy_looking_patterns_still_search_the_whole_line(self):
        # a lazy a+? followed by $ would stop early in Perl; in ERE it is just a+ then end-of-line
        self.assertTrue(rx.search_lines(rx.ere_to_py("^a+?$"), b"aaa\n"))
        self.assertTrue(rx.search_lines(rx.ere_to_py("^a*?$"), b"aaa\n"))
        self.assertFalse(rx.search_lines(rx.ere_to_py("^a++$"), b"\n"))


class Simplifier(unittest.TestCase):
    PATTERNS = ["(a+)+", "(a*)*", "(a+)*", "(a*)+", "(a?)*", "(a?)+", "(a+)?", "(a*)?", "(a?)?", "((a+)+)+", "(a{2,3})*", "(a{2,3}){2}",
                "(a{1,3})*", "(a+){2,4}", "(a?){3}", "(a*){0,2}", "(^)*a", "(^)+a", "($)*", "(\\b)*a", "(ab+)+c", "x(a|b+)+y", "(a+)+$"]

    def test_flattened_equals_literal_on_all_short_strings(self):
        import itertools
        words = [b""] + [bytes(t) for n in range(1, 7) for t in itertools.product(b"ab", repeat=n)]
        for pat in self.PATTERNS:
            on = rx.ere_to_py(pat, simplify=True)
            off = rx.ere_to_py(pat, simplify=False)
            for w in words:
                with self.subTest(pattern=pat, word=w):
                    self.assertEqual(on.search(w) is not None, off.search(w) is not None)

    def test_flattened_equals_grep_when_available(self):
        if not live_grep_available():
            self.skipTest("no GNU grep")
        words = [b"", b"a", b"aa", b"aaa", b"aaaa", b"aaaaa", b"ab", b"abc", b"abbc", b"ababc", b"xaby", b"xay", b"b", b"c"]
        for pat in self.PATTERNS:
            on = rx.ere_to_py(pat)
            for w in words:
                with self.subTest(pattern=pat, word=w):
                    self.assertEqual(on.search(w) is not None, grep_q(pat, w + b"\n") == 0)

    def test_nested_repetition_is_linear(self):
        # (a+)+$ on a^N b backtracks exponentially in re unless it is flattened to a+$
        c = rx.ere_to_py("(a+)+$")
        t0 = time.perf_counter()
        self.assertFalse(c.search(b"a" * 5000 + b"b"))
        self.assertLess(time.perf_counter() - t0, 1.0)
        self.assertNotIn(b"(?:", rx.ere_to_py_source("(a+)+$"))


class PerLineSemantics(unittest.TestCase):
    """The bug a naive translation has: [^x], . and \\s crossing the end of a line."""

    def test_negated_class_does_not_cross_a_newline(self):
        c = rx.ere_to_py('"[^"]*"')
        self.assertTrue(rx.search_lines(c, b'say "hi" now\n'))
        self.assertFalse(rx.search_lines(c, b'say "hi\nthere" now\n'))  # python's "[^\"]*\" would match across the break
        self.assertTrue(re.search(rb'"[^"]*"', b'say "hi\nthere" now'))   # ...and plain re does
        self.assertEqual(grep_q('"[^"]*"', b'say "hi\nthere" now\n') if live_grep_available() else 1, 1)

    def test_dot_s_and_w_do_not_cross_a_newline(self):
        for pat in ("a.b", "a\\sb", "a\\Wb", "a[[:space:]]b", "a[[:cntrl:]]b", "a[^x]b"):
            with self.subTest(pattern=pat):
                self.assertFalse(rx.search_lines(rx.ere_to_py(pat), b"a\nb\n"))

    def test_anchors_are_line_anchors(self):
        c = rx.ere_to_py("^b$")
        self.assertTrue(rx.search_lines(c, b"a\nb\nc\n"))
        self.assertFalse(rx.search_lines(c, b"ab\nbc\n"))

    def test_empty_file_has_no_line_but_a_lone_newline_has_one(self):
        self.assertFalse(rx.search_lines(rx.ere_to_py("^$"), b""))
        self.assertTrue(rx.search_lines(rx.ere_to_py("^$"), b"\n"))
        self.assertFalse(rx.search_lines(rx.ere_to_py("x*"), b""))
        self.assertTrue(rx.search_lines(rx.ere_to_py("x*"), b"\n"))

    def test_final_newline_does_not_start_another_line(self):
        self.assertFalse(rx.search_lines(rx.ere_to_py("^$"), b"a\n"))
        self.assertTrue(rx.search_lines(rx.ere_to_py("^$"), b"a\n\n"))

    def test_matching_lines_reports_each_line_once(self):
        c = rx.ere_to_py("a+")
        data = b"xx\naa a\nyy\na\n"
        spans = list(rx.matching_lines(c, data))
        self.assertEqual([data[s:e] for s, e in spans], [b"aa a", b"a"])

    def test_crlf_keeps_the_carriage_return_in_the_line(self):
        self.assertTrue(rx.search_lines(rx.ere_to_py("a\r$"), b"a\r\n"))  # a literal CR in the pattern; \\r would be the letter r
        self.assertFalse(rx.search_lines(rx.ere_to_py("a$"), b"a\r\n"))
        self.assertTrue(rx.search_lines(rx.ere_to_py("a[[:space:]]*$"), b"a\r\n"))


class CaseInsensitive(unittest.TestCase):
    def test_negated_set_is_folded_before_it_is_negated(self):
        c = rx.ere_to_py("[^a-c]", True)
        self.assertFalse(rx.search_lines(c, b"ABC\n"))
        self.assertTrue(rx.search_lines(c, b"D\n"))

    def test_ascii_only(self):
        c = rx.ere_to_py("k", True)
        self.assertTrue(rx.search_lines(c, b"K\n"))
        self.assertFalse(rx.search_lines(c, "K\n".encode()))  # the Kelvin sign is not a k in the C locale

    def test_backreference_ignores_case(self):
        c = rx.ere_to_py("(ab)\\1", True)
        self.assertTrue(rx.search_lines(c, b"abAB\n"))


class Excl(unittest.TestCase):
    def test_a_line_matching_both_is_excluded(self):
        self.assertTrue(rx.search_excl("secret", "example", b"secret=abc\nexample secret\n"))
        self.assertFalse(rx.search_excl("secret", "example", b"example secret\nEXAMPLE SECRET\n"))
        self.assertFalse(rx.search_excl("secret", "example", b"nothing\n"))

    def test_both_patterns_are_case_insensitive(self):
        self.assertFalse(rx.search_excl("secret", "example", b"SECRET example\n"))
        self.assertTrue(rx.search_excl("secret", "example", b"SECRET exempt\n"))

    def test_exclusion_only_looks_at_the_same_line(self):
        self.assertTrue(rx.search_excl("secret", "example", b"example\nsecret\n"))

    def test_binary_file_blind_spot_is_selectable(self):
        data = b"secret\x00\n"
        self.assertTrue(rx.search_excl("secret", "zzzz", data))
        self.assertFalse(rx.search_excl("secret", "zzzz", data, binary="grep"))

    @unittest.skipUnless(live_grep_available(), "GNU grep not available")
    def test_against_the_helper_pipeline(self):
        script = 'grep -hiE -e "$1" 2>/dev/null | grep -viE -e "$2" >/dev/null'
        for data in (b"secret=abc\nexample secret\n", b"example secret\n", b"x\n", b"SECRET\n", b"", b"\n", b"secret"):
            with self.subTest(data=data):
                p = subprocess.run(["bash", "-c", script, "_", "secret", "example"], input=data, capture_output=True, env=ENV)
                self.assertEqual(rx.search_excl("secret", "example", data), p.returncode == 0)


class Flat(unittest.TestCase):
    def test_view_folds_cr_lf_and_tab_only(self):
        self.assertEqual(rx.flat_view(b"a\r\nb\tc\nd e\x0bf"), b"a  b c d e\x0bf")

    def test_a_declaration_split_over_lines_is_found(self):
        c = rx.ere_to_py("<!ENTITY[^>]*[[:space:]]SYSTEM[[:space:]]+[\"'](file:|/)", True)
        doc = b"<!ENTITY\n  xxe\n\tSYSTEM\r\n\"file:///etc/passwd\">\n"
        self.assertFalse(rx.search_lines(c, doc))
        self.assertTrue(rx.search_flat(c, doc))

    def test_the_view_is_one_line_so_a_negated_class_may_cross_what_was_a_break(self):
        c = rx.ere_to_py('"[^"]*"', True)
        self.assertTrue(rx.search_flat(c, b'"a\nb"'))
        self.assertFalse(rx.search_lines(c, b'"a\nb"'))

    def test_the_cap_skips_the_file_it_does_not_cut_it(self):
        c = rx.ere_to_py("needle")
        at = b"needle" + b" " * (rx.FLAT_CAP - 6)
        self.assertEqual(len(at), rx.FLAT_CAP)
        self.assertTrue(rx.search_flat(c, at))
        self.assertFalse(rx.search_flat(c, at + b" "))
        self.assertFalse(rx.search_flat(c, b" " * rx.FLAT_CAP + b"needle"))

    def test_empty_input(self):
        self.assertFalse(rx.search_flat(rx.ere_to_py("x*"), b""))
        self.assertTrue(rx.search_flat(rx.ere_to_py("x*"), b"\n"))  # one blank line once the newline is a space

    @unittest.skipUnless(live_grep_available(), "GNU grep not available")
    def test_against_the_helper_pipeline(self):
        script = "tr '\\r\\n\\t' '   ' | grep -iE -e \"$1\" >/dev/null"
        pat = "a[[:space:]]+b$"
        c = rx.ere_to_py(pat, True)
        for data in (b"a\nb", b"a\nb\n", b"A\r\n\tB", b"ab", b"a b\n", b"a  b  ", b"", b"\n"):
            with self.subTest(data=data):
                p = subprocess.run(["bash", "-c", script, "_", pat], input=data, capture_output=True, env=ENV)
                self.assertEqual(rx.search_flat(c, data), p.returncode == 0)


class Binary(unittest.TestCase):
    def test_modes_match_grep(self):
        if not live_grep_available():
            self.skipTest("no GNU grep")
        for pat, data in (("^a", b"x\x00a\n"), ("a.b", b"a\x00b\n"), ("b.*a", b"b\x00a\n"), ("a$", b"a\x00\n"), ("a", b"\x00a\n")):
            c = rx.ere_to_py(pat)
            with self.subTest(pattern=pat, data=data):
                self.assertEqual(rx.search_lines(c, data, binary="grep"), grep_q(pat, data) == 0)
                self.assertEqual(rx.search_lines(c, data, binary="text"), grep_q(pat, data, extra=("-a",)) == 0)
        self.assertEqual(rx.search_lines(rx.ere_to_py("a"), b"a\x00b\n", binary="skip"), grep_q("a", b"a\x00b\n", extra=("-I",)) == 0)

    def test_bad_mode(self):
        with self.assertRaises(ValueError):
            rx.search_lines(rx.ere_to_py("a"), b"a", binary="nope")


class OnlyMatching(unittest.TestCase):
    @unittest.skipUnless(live_grep_available(), "GNU grep not available")
    def test_against_grep_o(self):
        data = b"Severity: HIGH and Severity: LOW\nnothing\nSeverity: \n  Severity: x1_ y\n"
        for pat in ("Severity: \\w+", "[a-z]+", "B[0-9]+", "(error|warning):[^$]+", "x*"):
            want = subprocess.run([GREP, "-oE", "-e", pat], input=data, capture_output=True, env=ENV).stdout.split(b"\n")[:-1]
            with self.subTest(pattern=pat):
                self.assertEqual(rx.only_matching(rx.ere_to_py(pat), data), want)

    def test_empty_matches_are_skipped(self):
        self.assertEqual(rx.only_matching(rx.ere_to_py("x*"), b"axxb\n"), [b"xx"])


class AfterContext(unittest.TestCase):
    @unittest.skipUnless(live_grep_available(), "GNU grep not available")
    def test_against_grep_A(self):
        docs = [b"a\nx\nb\nc\nd\ne\nf\ng\nx\nh\n", b"x\n", b"x", b"x\nx\nx\n1\n2\n3\n4\n5\n6\nx\n", b"1\n2\n", b"",
                b"y\n\nx\n\n\n\n\n\n\n\nx\ny\n", b"x\r\ny\r\n"]
        c = rx.ere_to_py("x")
        for n in (0, 1, 2, 5):
            for d in docs:
                with self.subTest(n=n, data=d):
                    want = subprocess.run([GREP, "-E", f"-A{n}", "-e", "x"], input=d, capture_output=True, env=ENV).stdout
                    self.assertEqual(rx.after_context(c, d, n), want)


class Guard(unittest.TestCase):
    def test_time_limit_interrupts_a_runaway_match(self):
        runaway = re.compile(rb"(a|aa)+$")
        t0 = time.perf_counter()
        with self.assertRaises(rx.RegexTimeout):
            with rx.time_limit(0.5):
                runaway.search(b"a" * 60 + b"b")
        self.assertLess(time.perf_counter() - t0, 3.0)

    def test_time_limit_is_quiet_when_not_needed(self):
        with rx.time_limit(5):
            self.assertTrue(rx.ere_to_py("a").search(b"a"))

    def test_lines_over(self):
        self.assertEqual(rx.lines_over(b"ab\n" + b"x" * 100 + b"\nc", 10), 1)
        self.assertEqual(rx.lines_over(b"ab", 10), 0)


class LinearMatcher(unittest.TestCase):
    """The DFA that takes over from re on a pathological line must give the same answers as re and as grep."""

    PATTERNS = [r"a+b", r"^foo", r"bar$", r"\bfoo\b", r"x[^y]*z", r"(ab|cd)+e", r"^$", r"\<a", r"a\>", r"\Ba", r"a{2,3}b",
                r"[[:space:]]+$", r"(a|b)*abb", r"", r"x*", r"^a|b$", r"a\W+b", r"(^| )x( |$)", r"o{3,}", r"[^a-c]d", r"a.*b.*c"]

    def test_matches_re_on_random_buffers(self):
        import random
        rnd = random.Random(11)
        alpha = b"abxyzcd \n_foo-"
        for pat in self.PATTERNS:
            for ci in (False, True):
                c = rx.ere_to_py(pat, ci)
                self.assertTrue(rx.dfa_available(c))
                for _ in range(250):
                    d = bytes(rnd.choice(alpha) for _ in range(rnd.randint(0, 30)))
                    with self.subTest(pattern=pat, ci=ci, data=d):
                        self.assertEqual(rx.dfa_search(c, d), rx.search_lines(c, d))
                        self.assertEqual(list(rx.dfa_matching_lines(c, d)), list(rx.matching_lines(c, d)))

    @unittest.skipUnless(live_grep_available(), "GNU grep not available")
    def test_matches_grep(self):
        for pat in self.PATTERNS:
            c = rx.ere_to_py(pat)
            for d in (b"", b"\n", b"foo\n", b"a foo b\nx\n", b"xz\nxyz\nxabz", b"aab", b"ab\ncd\nabcde", b"  \nx", b"o\nooo"):
                with self.subTest(pattern=pat, data=d):
                    self.assertEqual(rx.dfa_search(c, d), grep_q(pat, d) == 0)

    def test_no_dfa_for_a_back_reference(self):
        c = rx.ere_to_py("(a)\\1")
        self.assertFalse(rx.dfa_available(c))
        with self.assertRaises(ValueError):
            rx.dfa_search(c, b"aa")

    def test_cache_reset_does_not_change_answers(self):
        old = rx.MAX_DFA_STATES
        try:
            rx.MAX_DFA_STATES = 4
            rx._DFAS.clear()
            c = rx.ere_to_py("(a|b)*abb[^c]d")
            for d in (b"ababbxd", b"abbcd", b"zzabbxd\nqq", b"babababababb d", b"ab" * 200):
                with self.subTest(data=d):
                    self.assertEqual(rx.dfa_search(c, d), rx.search_lines(c, d))
        finally:
            rx.MAX_DFA_STATES = old
            rx._DFAS.clear()

    def test_counted_repetition_and_pem_shape(self):
        pat = "-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----.{0,200}[A-Za-z0-9+/]{60,}"
        c = rx.ere_to_py(pat)
        yes = b"-----BEGIN RSA PRIVATE KEY----- " + b"A" * 64
        no = b"-----BEGIN RSA PRIVATE KEY----- " + b"A" * 59
        self.assertTrue(rx.dfa_search(c, yes))
        self.assertFalse(rx.dfa_search(c, no))
        self.assertEqual(rx.dfa_search(c, no + b"=" + b"B" * 60), True)


class Budget(unittest.TestCase):
    """budget= : re for a while, then the linear matcher; the answer must not change and a line must not hide the next."""

    def hostile(self):
        pat = "curl[^|&]*http://"
        unit = b"curl x http:/ "
        return rx.ere_to_py(pat, True), unit * (65536 // len(unit))

    def test_a_pathological_line_is_bounded_and_correct(self):
        c, line = self.hostile()
        t0 = time.perf_counter()
        self.assertFalse(rx.search_lines(c, line + b"\n", budget=0.2))
        self.assertLess(time.perf_counter() - t0, 1.5)
        t0 = time.perf_counter()
        self.assertTrue(rx.search_lines(c, line + b"\ncurl http://evil.example/x\n", budget=0.2))
        self.assertLess(time.perf_counter() - t0, 1.5)

    def test_without_a_budget_the_same_line_is_slow(self):
        # the problem this exists for: re needs about two seconds on this line, grep a few milliseconds
        c, line = self.hostile()
        t0 = time.perf_counter()
        with self.assertRaises(rx.RegexTimeout):
            with rx.time_limit(0.3):
                c.search(line)
        self.assertLess(time.perf_counter() - t0, 1.5)

    def test_forced_timeout_uses_the_linear_matcher_everywhere(self):
        real = rx._guarded_search
        calls = []

        def always_late(compiled, d, pos, end, budget):
            calls.append(1)
            raise rx.RegexTimeout("forced")

        rx._guarded_search = always_late
        try:
            c = rx.ere_to_py("secret")
            ex = rx.ere_to_py("example", True)
            data = b"nothing\nsecret=1\nexample secret\nSECRET\n"
            self.assertTrue(rx.search_lines(c, data, budget=1))
            self.assertEqual(list(rx.matching_lines(c, data, budget=1)), [(8, 16), (17, 31)])
            self.assertEqual([data[a:b] for a, b in rx.excl_lines(rx.ere_to_py("secret", True), ex, data, budget=1)],
                             [b"secret=1", b"SECRET"])
            self.assertTrue(rx.search_excl("secret", "example", data, budget=1))
            self.assertTrue(rx.search_flat(rx.ere_to_py("t\\ns", True), b"a\nt\ns", budget=1) is False)
            self.assertTrue(rx.search_flat(rx.ere_to_py("t s", True), b"a\nt\ns", budget=1))
            self.assertTrue(calls)
            with self.assertRaises(rx.RegexTimeout):  # no linear matcher for a back-reference: the timeout is reported
                rx.search_lines(rx.ere_to_py("(a)\\1"), b"aa", budget=1)
        finally:
            rx._guarded_search = real

    def test_budget_none_is_the_plain_path(self):
        c = rx.ere_to_py("a+")
        self.assertTrue(rx.search_lines(c, b"xa\n", budget=None))


class Registry(unittest.TestCase):
    def test_rules_are_enumerable(self):
        r = rx.rule("test:one", "a+b", mode="line_i")
        e = rx.rule("test:two", "secret", mode="excl", excl="example")
        ids = [x.id for x in rx.registered()]
        self.assertIn("test:one", ids)
        self.assertIn("test:two", ids)
        self.assertIs(rx.rule("test:one", "a+b", mode="line_i").compiled, r.compiled)
        self.assertTrue(r.compiled.search(b"AAB"))
        self.assertIsNotNone(e.compiled_excl)
        with self.assertRaises(ValueError):
            rx.rule("test:one", "different", mode="line_i")
        with self.assertRaises(ValueError):
            rx.rule("test:three", "x", mode="excl")
        self.assertTrue(any(p == b"a+b" and ci for p, ci, _ in rx.compiled_patterns()))


if __name__ == "__main__":
    unittest.main(verbosity=1)
