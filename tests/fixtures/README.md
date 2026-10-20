# ELF shared-library fixtures

These fixtures are generated entirely from source in this repository and contain no third-party binaries:

- `libsymbolic.so` retains symbols and DWARF debug information.
- `libstripped.so` is optimized and stripped of ordinary symbols and debug information while retaining exports.
- `libcontrol_flow.so` uses runtime state loops and function-pointer dispatch to produce indirect control flow similar to control-flow flattening.

Build the fixtures:

```bash
python scripts/build_fixtures.py
```

SHA-256 values produced with Zig 0.16.0 on 2026-07-20:

```text
f87e3005d28ad1751b90b088eaa6f3f73c788fe1f3f605cbc9a210726febdc96  libsymbolic.so
f7f4ef287303b0de81bb0e43723f8bf654d3261e9f1b4c5237f94bd71585c590  libstripped.so
51e50c32193c666dc2ace38935477cd88eea901ab77fc1dfdcd602647677888a  libcontrol_flow.so
```

## APK sample (not committed)

`tests/integration/test_real_ghidra_apk_reopen.py` uses a small open-source APK, the F-Droid Privileged Extension 0.2.13 (`org.fdroid.fdroid.privileged`, Apache-2.0, about 46 KB). It is a third-party binary, so it is not committed and the test is skipped when it is missing. Fetch it into the ignored `generated/` directory and check its hash:

```bash
curl -fsSL -o tests/fixtures/generated/org.fdroid.fdroid.privileged_2130.apk \
  https://f-droid.org/repo/org.fdroid.fdroid.privileged_2130.apk
echo "1008525a17b4f6a93ac690f9c50dcb675b6bebf53d2879dbc98ba65a1cb2e28d  tests/fixtures/generated/org.fdroid.fdroid.privileged_2130.apk" \
  | sha256sum -c -
```

Run the real Ghidra tests:

```bash
mkdir -p /tmp/ghidra-mcp-java-home
GHIDRA_INSTALL_DIR=/path/to/ghidra \
  _JAVA_OPTIONS=-Duser.home=/tmp/ghidra-mcp-java-home \
  python -m pytest tests/integration/test_real_ghidra.py -q -s
```

The temporary `user.home` prevents tests from modifying the user's Ghidra configuration.
