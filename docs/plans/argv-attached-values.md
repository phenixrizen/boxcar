# Argv values attached to a secret word

**Goal.** In an argv each argument is one word, so a value attached to a secret-looking name runs to the argument's end. `scrub_arg` (`crates/boxcar-proto/src/redact.rs`), used by `scrub_argv` for `proc.exec` and `session.start` under `--scrub-argv` and by `scrub_deep` for every string inside a JSON array (tool arguments, the observer's and the dump's decoded bodies), redacts such a value whole.

Five review rounds on rule-by-rule recognition (a whitelist of name characters, then prefixes, quotes, colons, brackets) each found another spelling. This plan replaces recognition with one rule over what main already does, and reviews it before the code follows.

## The rule

1. The argument goes through main's rules unchanged: a user flag's value (`--user=alice:pw`, `-ualice:pw`) through `user_value`, anything else through `scrub_text`.
2. Then, in the result, the first `=` or `:` whose text before it is **one word** (no whitespace) holding a secret's stem (`is_secret_key`, case-insensitive) or `basic` is found, and everything after it, to the argument's end, becomes `[redacted]`, if anything is there.

The word before the separator is not parsed as a name, so every spelling holds: `--cookie=a; b=c`, `--password=a b`, `API_TOKEN=a b`, `+password=`, `/password=`, `'password'=`, `-Ddb.password=`, `-Ddb[0].password=`, `--Db:Password=`, `--Service:ApiKey=a;b`, `Authorization: Basic a b`, `Basic=a b`, `-user-password=a b:c`, `-u<credential>=x:pw`.

Step 2 is computed in one pass. Only the argument's first word can qualify, since any later separator has whitespace before it. That word is lowercased once (ASCII, which keeps byte offsets; every stem is ASCII). The end of the first stem (or `basic`) in it is found. The separator is the first `=` or `:` at or after that end, within the word.

## Invariants

- **I1. Never less than main.** Step 1 is main's `scrub_arg`, and step 2 only replaces a suffix with `[redacted]`. Whatever main redacts stays redacted, and what main keeps is kept only where step 2 does not apply. A gap left by this rule is one main has too, never a new one.
- **I2.** A value attached by `=` or `:` to a one-word argument holding a secret's stem never survives in part, whatever characters the word holds.
- **I3.** A script given to a shell (`sh -c 'export TOKEN=x; rm -rf /tmp/y'`) has whitespace before its separators. It stays with the text rules, and its later commands stay in the record.
- **I4. Linear time** in the argument's length. Strings in arrays on the observer and dump paths can be megabytes, without whitespace (minified JSON in a string) and with many separators.
- **I5. Stable.** Scrubbing a scrubbed argument changes nothing.
- **I6. No panic** on any input. Slicing happens only at ASCII separators found in the same string, never at offsets computed in another string.
- **I7.** `is_secret_flag` is unchanged. A secret flag without `=` (`--token`, `--Secrets:ApiKey`) still redacts the next argument whole.

## Out of scope

- Values in an argument of their own after a flag whose name holds no stem, as on main.
- Names holding no stem (`--pw=`, `--key=`): `is_secret_key`'s stems are the module's single list, and widening them is a change of its own.
- Free text: the text rules' behaviour on main.
- Over-redaction is accepted, as `scrub`'s doc says: `--max_tokens=8` loses its value. The reconciler compares commands with the argv as run (`RawArgv`), so it is not affected.

## Tests

- `a_value_attached_to_a_secret_name_is_taken_whole_in_an_argv`: every spelling above, through `scrub_argv` and `scrub_deep`, plus a second scrub (I2, I5). Also the `-u` credentials, the script (I3), and `--Secrets:ApiKey VALUE` and `--password:x next` (I7).
- `a_long_argument_scrubs_in_linear_time` (new): a 2 MiB argument without whitespace, made of `a:` pairs, then the same with a stem near its end. Each scrubs within a second; a quadratic scan takes minutes (I4).
- I1 is structural and holds by construction (step 1 is main's code). No test can enumerate it; the review checks it.
- The existing redaction and audit tests pass unchanged (`random_text_never_panics` covers I6).
