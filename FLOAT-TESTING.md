# Transport-endpoint / float invariant regression test

## Scope and method

The standalone test modules execute `ovpn_peer_endpoints_update()` extracted unchanged from the before/after Ubuntu `peer.c` sources. They also use the extracted `ovpn_peer_reset_sockaddr()` and copied production `bind.c` helpers and headers. Private allocated objects include a peer, its tables, destination cache, an unregistered net device, and synthetic packet headers.

Each module runs IPv4 and IPv6 cases. First it enters an active peer in the ID and transport tables and invokes an endpoint change. It verifies the binding changed, the transport node remains linked, and one transport bucket is occupied. It then directly unlinks the ID and transport entries while retaining the allocated peer, supplies a further endpoint change, and invokes the function again. The endpoint must update in both variants; the removed peer must remain unhashed only in the patched variant. Any baseline reinsertion is unlinked during cleanup.

The addresses are documentation-only IPv4/IPv6 keys in private memory, with synthetic UDP headers. No sockets, routes or registered interfaces are created, no packets are transmitted, and no real VPN configuration is modified. The existing `ovpn` module remains loaded.

This exercises a function-level post-removal state, not the actual concurrent scheduling window, a peer use-after-free, or the full production peer deletion routine. The normal `io.c` caller reaches this function in the UDP receive path after packet authentication and packet-ID checking; those upstream checks are not exercised here. Bucket occupancy and node linkage are checked, not every production lookup by endpoint.

## Recorded run

2026-10-06, Europe/Berlin local time. Ubuntu kernel `7.0.0-38-generic`, reviewed source package `linux 7.0.0-38.38`, x86_64 Hyper-V VM, Secure Boot disabled. Matching Ubuntu GCC 15.2.0-16ubuntu1 and headers. Both builds completed; missing `vmlinux` prevented BTF generation, and a pahole version warning was reported. KASAN, KCSAN, PROVE_LOCKING and DEBUG_LOCK_ALLOC were disabled.

Operator-supplied kernel log output:

```text
11:27:57 ovpn-float-regtest before IPv4: active=PASS endpoint-update=PASS removed-invariant=FAIL occupied=1 expected=PASS
11:27:57 ovpn-float-regtest before IPv6: active=PASS endpoint-update=PASS removed-invariant=FAIL occupied=1 expected=PASS
11:28:43 ovpn-float-regtest after IPv4: active=PASS endpoint-update=PASS removed-invariant=PASS occupied=0 expected=PASS
11:28:43 ovpn-float-regtest after IPv6: active=PASS endpoint-update=PASS removed-invariant=PASS occupied=0 expected=PASS
```

Baseline `expected=PASS` means the known invalid reinsertion occurred. It does not mean the removal invariant passed. Both active-peer cases and endpoint-update checks passed; only the patched functions preserved the removed-peer invariant.

After the run no float or VPN-IP test modules were listed by `lsmod`. The administrative VPN service was active with its pre-test address unchanged. The reviewed log interval from 11:27 contained these four lines and no matching BUG, Oops, general protection fault or soft lockup lines. This is a bounded log observation, not sanitizer evidence or a whole-system health audit.

Recorded hashes of transferred binaries (binaries are not distributed):

```text
f9d2cdaf16b2df449c2e5c98662988a1d117b6cd16963bcf40e6a918372d9ed5  ovpn_float_before.ko
c854065af04d1b72378c3f4dad9824b05810f104058869f2df115c213d3880bd  ovpn_float_after.ko
```

## Reproduction

Use a compatible disposable VM with console access. New kernel test code can crash the entire kernel; private test objects are not a crash-isolation boundary. Unsigned out-of-tree modules can taint the kernel. Keep original distribution module files unchanged.

Prepare the before/after source layout described in [TESTING.md](TESTING.md). Copy `tests/prepare-ovpn-float-regtest.py` into the Ubuntu source root's parent directory. The generator verifies the recorded patch checksum, checks for absence/presence of the guard, checks that supporting macros and reset function match, and refuses to overwrite an existing `ovpn-float-regtest` directory.

From the source root:

```sh
python3 ../prepare-ovpn-float-regtest.py
make -C /lib/modules/7.0.0-38-generic/build \
  M="$PWD/../ovpn-float-regtest/before" \
  CC=x86_64-linux-gnu-gcc -j1 modules
make -C /lib/modules/7.0.0-38-generic/build \
  M="$PWD/../ovpn-float-regtest/after" \
  CC=x86_64-linux-gnu-gcc -j1 modules
```

Review generated source. Check checksums and vermagic after transferring the two `.ko` files to the test VM. From their directory, run each variant separately and inspect its fresh output before continuing:

```sh
sudo insmod ./ovpn_float_before.ko && sudo rmmod ovpn_float_before
sudo journalctl -k -b --no-pager | grep -F 'ovpn-float-regtest before' | tail -n 2
sudo insmod ./ovpn_float_after.ko && sudo rmmod ovpn_float_after
sudo journalctl -k -b --no-pager | grep -F 'ovpn-float-regtest after' | tail -n 2
```

Match timestamps to the current run. Unexpected test results or allocation failures cause initialization to fail; do not treat stale log lines as evidence of a successful new run. Inspect kernel errors and confirm test modules are unloaded after testing. Binary build reproducibility is not asserted.

## Subsequent KASAN-enabled run

The same synthetic test was rebuilt and rerun on `7.0.14-ovpn-kasan` on 2026-10-06. Both IPv4/IPv6 variants produced the same expected state results and the supplied filtered log contained no KASAN errors. See [KASAN-TESTING.md](KASAN-TESTING.md) for the exact output, configuration and new binary hashes. This later execution did not change the test's synthetic removal method or its lifetime limitations.

## Remaining limits

Both modified functions have deterministic before/after state tests, and the float test has also run under KASAN. Concurrent race reproduction, runtime validation of the actual reference-count and RCU peer teardown, authenticated traffic integration tests, sustained load, and KCSAN/lockdep runs remain outstanding. No supplemental lifecycle test was completed. These results are not complete security validation.
