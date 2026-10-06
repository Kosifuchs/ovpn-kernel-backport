# VPN-IP rehash invariant regression test

## Scope

This test executes the actual VPN-IP rehash function from two source versions in standalone kernel modules. It allocates private `ovpn_priv`, peer and hash-table objects, enters an active synthetic peer, unlinks its entries while retaining allocated storage, then calls the rehash function again under the required lock.

IPv4 and IPv6 entries and occupied buckets are checked. The test performs no real peer lookup, creates no interfaces, sockets or routes, sends no packets and does not register OpenVPN link or netlink operations. It neither replaces nor requires unloading the operational `ovpn` module.

The test models the completed hash-table removal directly with list operations. It does not call the full production peer removal routine, its notifications, reference-count callbacks or deferred free logic. The copied function and headers come from the reviewed Ubuntu source; this is not a test invoking the operational module's function through its API.

## Recorded environment and results

Ubuntu kernel `7.0.0-38-generic`, source package `linux 7.0.0-38.38`, x86_64 Hyper-V VM, Secure Boot disabled, matching Ubuntu GCC 15.2.0-16ubuntu1. KASAN, KCSAN, PROVE_LOCKING, DEBUG_LOCK_ALLOC, DEBUG_LIST and KUnit were disabled. Results are operator-supplied terminal output from 2026-10-06, local time Europe/Berlin.

Both module builds completed. BTF generation was skipped due to missing `vmlinux`; the pahole version warning did not prevent compilation.

```text
07:27:55 ovpn-regtest before: active=PASS removed-invariant=FAIL occupied4=1 occupied6=1 expected=PASS
07:28:32 ovpn-regtest after: active=PASS removed-invariant=PASS occupied4=0 occupied6=0 expected=PASS
```

`expected=PASS` in the baseline means that the known incorrect reinsertion was observed, not that the security invariant passed. The invariant passes only in the patched variant. Both variants retain correct insertion of an active synthetic peer.

After unloading both test modules, none remained listed in `lsmod`. The operational VPN service was active with its pre-test address. The reviewed kernel log interval contained these two results and no matching BUG, Oops, general protection fault or soft lockup lines. This log check is not evidence that KASAN ran.

Recorded artifact hashes (no binaries distributed):

```text
8639a8d3575e5f072d106a8cdd644b042533dd69facb440372d04339d920e85f  ovpn_regtest_before.ko
5c8a5942bc3e2759baae4feaaf1f5fba7b2b36dbc14bef4db61df9eab930e5cb  ovpn_regtest_after.ko
```

## Reproduction

Use a disposable compatible VM with console access. Any newly written kernel test code can crash the kernel. Keep production modules unchanged. Loading these unsigned out-of-tree modules can taint the kernel.

Prepare the exact Ubuntu source and matching headers. Before applying the upstream patch, save the original `drivers/net/ovpn/peer.c` as `peer.c.vor-CVE-2026-74727` in the source root's parent directory. Place `CVE-2026-74727-upstream.patch` in that same parent directory and apply it to the source tree as described in README.md. The generator verifies the patch checksum, checks for absence/presence of the guard and refuses to overwrite an existing test directory.

Copy `tests/prepare-ovpn-rehash-regtest.py` to the source root's parent directory. From the source root:

```sh
python3 ../prepare-ovpn-rehash-regtest.py
make -C /lib/modules/7.0.0-38-generic/build \
  M="$PWD/../ovpn-rehash-regtest/before" \
  CC=x86_64-linux-gnu-gcc -j1 modules
make -C /lib/modules/7.0.0-38-generic/build \
  M="$PWD/../ovpn-rehash-regtest/after" \
  CC=x86_64-linux-gnu-gcc -j1 modules
```

Review generated source and confirm hashes and vermagic before transferring the two `.ko` files to the test VM. In the directory containing those files, test each variant separately:

```sh
sudo insmod ./ovpn_regtest_before.ko && sudo rmmod ovpn_regtest_before
sudo journalctl -k -b --no-pager | grep -F 'ovpn-regtest before:' | tail -n 3
sudo insmod ./ovpn_regtest_after.ko && sudo rmmod ovpn_regtest_after
sudo journalctl -k -b --no-pager | grep -F 'ovpn-regtest after:' | tail -n 3
```

Match output to the current run rather than accepting an older matching log line. Unexpected insertion results or allocation failures cause module initialization to fail. Kernel build reproducibility, including exact binary hashes, is not asserted.

## Remaining validation

- No concurrent scheduling window was exercised or deletion/rehash race reproduced.
- The transport-endpoint / float path was not exercised by this VPN-IP test; a separate deterministic synthetic test is documented in [FLOAT-TESTING.md](FLOAT-TESTING.md).
- This VPN-IP test was not rerun under KASAN. The separate float test was rerun on a Generic KASAN kernel; see [KASAN-TESTING.md](KASAN-TESTING.md). No KCSAN, lockdep or sustained concurrency run was performed.
- Source inspection and this focused invariant test are not complete driver or kernel security validation.

The original generator's unsupported `INIT_HLIST_NULLS_NODE` calls caused a build failure before any test module was loaded. They were removed because the synthetic nodes are already zero-initialized by `kzalloc`; the corrected modules then built and produced the recorded results. The published generator includes this correction.
