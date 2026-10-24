# Argv values attached to a secret word

**Goal.** In an argv each argument is one word, so a value attached to a secret-looking name runs to the argument's end. `scrub_arg` (`crates/boxcar-proto/src/redact.rs`), used by `scrub_argv` for `proc.exec` and `session.start` under `--scrub-argv` and by `scrub_deep` for every string inside a JSON array (tool arguments, the observer's and the dump's decoded bodies), redacts such a value whole.

Five review rounds on rule-by-rule recognition (a whitelist of name characters, then prefixes, quotes, colons, brackets) each found another spelling. This plan replaces recognition with one rule over what main already does, and reviews it before the code follows.

## The rule

For an argument `A`, with `M` what main makes of it in its place: after a separate user flag (`-u`, `--user`), `user_value` then `scrub_text`; otherwise main's `scrub_arg`, a user flag's attached value through `user_value` and anything else through `scrub_text`. After a secret flag the argument is redacted whole, as on main, and nothing below applies.

1. **Code stays text, except a leading secret assignment.** When `A` follows `-c`, `-e`, `--command` or `--eval`, or a short-flag cluster ending in `c` or `e` (`-lc`, `-ec`), `A` is code: the result is normally `M`, and the script's later commands stay in the record. When it starts with a portable shell `NAME=` and `NAME` is a secret key, the cut applies and its value runs to the argument's end. Thus `sh -c 'echo retained; TOKEN=x'` keeps the script after applying the text rules, while `docker run -e 'TOKEN=a b'` becomes `TOKEN=[redacted]`. The test is by position and the leading assignment's shape, both read from `A`.
2. **The cut, found in `A`.** The rule looks at `A`'s first word only (up to the first whitespace). The cut is the first `=` or `:` in that word that comes after a secret's stem (`SECRET_STEMS`, or `basic`) in the word lowercased as `is_secret_key` reads it (Unicode `to_lowercase`, so `toKen` with the Kelvin sign counts), or follows one of the exact secret names, with something after it in `A`. With no cut, the result is `M`.
3. **The result, never less than `M`.** With the cut at byte `p` and `P = A[..=p]`: when `M` starts with `P`, main left all of `P` as it was, and the result is `P` followed by `[redacted]`. Otherwise main redacted something inside `P` (a long name taken for a credential, a `-u` user that is one), and the result is `[redacted]`, the whole argument.

4. **The next argument.** Main redacts the argument after a bare secret flag (`is_secret_flag`: `--token`, `--Secrets:ApiKey`). A cut can make an argument a bare secret flag where it was not one: `--toKen:x=y` (the Kelvin sign) becomes `--toKen:[redacted]`, which has no `=`. So an argument counts as a secret flag for the next one when either it as given or its result is one, and the next argument goes in the first pass, not only on a second scrub.

   The other flags that shape the next argument are read from the result, as a second scrub reads them. A user flag counts when its result is one. A `-u` that was itself redacted as a secret flag's value makes the next argument go whole: main would still read it as `user:password`, and whole is never less than that. A code flag counts only when its result is one. A `-c` redacted as a secret flag's value (`--token -c 'TOKEN=x; echo'`) is no code flag, so the next argument gets the cut in the first pass too. The code rule gives either main's result or the leading-assignment cut through it, so this cannot redact less than main.

5. **A fixed point.** Outside code, the result is scrubbed again in the same place. If that would change it (a cut removed the colon an attached `-u` needs, so the second pass reads the argument differently), the argument goes whole. With step 4 the flags are read alike on both passes, so such an argv scrubs the same way twice by construction, not case by case. Code keeps `M` as it is unless the leading-assignment cut applies: replacing any other whole script because main's text rules are not a fixed point on it would lose its later commands (I3). There it is as stable as main's text rules, whose own instability on a quoted `-u` value ending in `;` is #40. A code argument also keeps main's reading of it for the next argument, from the argument as given, so a script's instability does not change how the argument after it is read.

Recognition reads `A`, not `M`, so main's own redactions cannot hide the stem (`--password<32 digits>=alpha beta` loses `beta`). Applying it through `M` keeps every redaction main makes.

The word before the separator is not parsed as a name, so every spelling holds: `--cookie=a; b=c`, `--password=a b`, `API_TOKEN=a b`, `+password=`, `/password=`, `'password'=`, `-Ddb.password=`, `-Ddb[0].password=`, `--Db:Password=`, `--Service:ApiKey=a;b`, `Authorization: Basic a b`, `Basic=a b`, `-user-password=a b:c`, `-u<credential>=x:pw`.

Step 2 runs in one pass, linear in the word's length:
- The word is lowercased once, char by char, keeping for each lowered byte the end of the original char it came from.
- The first occurrence of each stem gives the earliest stem end, mapped back to the word.
- The cut is the first `=` or `:` at or after that end.

Stems hold neither `=` nor `:`, so this is the first separator whose text before it holds a stem. Step 3's prefix test is linear too.

## Invariants

- **I1. Never less than main.** The result is `M`, or `M` with everything after an untouched prefix replaced, or `[redacted]`. Whatever main redacts stays redacted. This holds by construction.
- **I2.** A value attached by `=` or `:` to a first word holding a secret's stem never survives in part, outside code arguments that do not start with a secret assignment, whether the argument stands alone or follows a user flag.
- **I3.** Code after a code flag keeps its later commands unless it starts with a secret assignment; otherwise the text rules apply to it as on main, on every scrub.
- **I4. Linear time** in the argument's length. Strings in arrays on the observer and dump paths can be megabytes, without whitespace and with many separators.
- **I5. Stable**, for an argument and for an argv. The exceptions are code and the argument right after it, which are as stable as main's text rules (#40). Scrubbing a scrubbed argument changes nothing: the cut is found again in `P[redacted]`, main leaves `P[redacted]` alone, and `[redacted]` has no stem. Scrubbing a scrubbed argv changes nothing either. Step 4 reads every flag from the result, as the second pass does: a secret flag also from the argument, and that only redacts the next argument whole, a fixed point in any place. Step 5 makes each result a fixed point in its place.
- **I6. No panic** on any input. Slices are taken only at char boundaries of the same string, from `char_indices` or from ASCII separators found there.
- **I7.** An argument `is_secret_flag` takes as a flag redacts the next argument whole (`--token`, `--Secrets:ApiKey`, `--key`). Step 4 only adds flags, never removes one.

## Out of scope

- Values in an argument of their own after a flag whose name holds no stem, as on main.
- Names holding neither a stem nor one of the module's exact secret names (`--pw=`).
- Code given other than after a code flag (a remote command to `ssh`, an awk program). The cut can apply to it, and its text is lost from the argument's record. What it runs locally is still recorded by its own `proc.exec` and its effects.
- A value after `-e` or `-c` that is not a leading secret `NAME=` assignment is taken as code, whatever program owns the flag. Telling other environment-value shapes from code would need a program's own syntax.
- Over-redaction is accepted, as `scrub`'s doc says: `--max_tokens=8` loses its value. The reconciler compares commands with the argv as run (`RawArgv`), so it is not affected.

## Tests

- `a_value_attached_to_a_secret_name_is_taken_whole_in_an_argv`: every spelling above, through `scrub_argv` and `scrub_deep`, plus a second scrub (I2, I5). Also:
  - `--password<32 digits>=alpha beta` and `-u<credential>=x:pw`: step 3's whole-argument case;
  - `--toKen=alpha beta` with the Kelvin sign: Unicode recognition;
  - `--Secrets:ApiKey VALUE` and `--password:x next` (I7);
  - `--toKen:x=y` (the Kelvin sign) then `keep`: `keep` is redacted in the first pass, and a second pass changes nothing, through both entry points (step 4, I5);
  - flags redacted as a secret flag's value: `--token -c 'TOKEN=x; echo retained'` and `--token -u alice:pw`, stable over two passes, through both entry points (step 4, I1, I5);
  - `-usecret'x=alice:pw` and its `-U` form: the cut removes the colon, and the argument goes whole (step 5).
- `a_script_keeps_what_main_keeps` (new): `sh -c "curl … -u 'alice:pw'; echo retained"` keeps main's result, its later command included (I3).
- `argvs_of_flag_pieces_scrub_stably` (new): 2,000 argvs built from the pieces of flags and values (user, secret and code flags, stems, separators, quotes, the redaction mark) scrub the same way twice and alike through both entry points (I5).
- `code_after_a_code_flag_stays_text` (new): scripts without a leading secret assignment keep their later commands through both entry points and on a second scrub (I3, I5). `a_leading_secret_assignment_after_a_code_flag_is_cut` covers every code-flag spelling and both entry points. `env 'TOKEN=a b'` and `--cookie=a; b=c`, which follow no code flag, are cut too.
- A user flag's separate value: `curl -u 'token=alpha beta:pw'` and `--user 'password=a b:c'` lose the whole attached value, through both entry points (I2).
- `a_long_argument_scrubs_in_linear_time` (new): a 2 MiB argument without whitespace, made of `a:` pairs, then one with a stem near its end, then one of Kelvin-sign letters. Each scrubs within a second; a quadratic scan takes minutes (I4).
- `random_argvs_never_panic` (new): random arrays of random strings (separators, multi-byte characters, quotes) through `scrub_argv` and `scrub_deep` (I6). Each result is also scrubbed again to check I5.
- I1 holds by construction; the review checks it. The existing redaction and audit tests pass unchanged.
