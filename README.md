# OpenVPN kernel module backport review

Documentation of a local build, functional tests and deterministic VPN-IP and transport-endpoint rehash invariant regression tests of the upstream fix associated with CVE-2026-74727, against Ubuntu kernel source package `linux 7.0.0-38.38` on x86_64.

## Attribution and scope

This is a backport review of an existing upstream fix, not a newly discovered vulnerability or an original security fix. The recorded upstream author is Antonio Quartulli. The recorded commit is `33ec10567fe14456063daf549fdf1a4f53448e4c`.

Upstream patch: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/patch/?id=33ec10567fe14456063daf549fdf1a4f53448e4c

The change in `drivers/net/ovpn/peer.c` prevents rehashing a peer that has already been removed from the peer ID hash table. Preserve the original patch headers, authorship and licensing when distributing it. This documentation does not relicense the kernel patch.

The original upstream patch is included byte-for-byte. Its SHA-256 matches the artifact used in the recorded test session. Its author, commit message and code changes were checked against the public upstream commit on GitHub. No binary is included.

## Recorded checksums

The patch checksum was independently checked against the included file. The module checksum was recorded during the operator's test session; the binary is not distributed here.

| Artifact | SHA-256 |
| --- | --- |
| `CVE-2026-74727-upstream.patch` | `baf0962c60b182776a86e040d2ec5b35eea2737c2e2eb6f17f87eb7d2fe47b24` |
| Tested `ovpn.ko` | `0853fdce14ce1c4d64857871dc873bf98a1b8fe8243bf042ad6daffc906e6d27` |

## Apply and build

Use a separate extracted copy of the exact Ubuntu source package `linux 7.0.0-38.38`. Install matching kernel headers and the build toolchain first. The recorded compiler was Ubuntu GCC 15.2.0-16ubuntu1, matching the running kernel's compiler.

From the source root, with the patch in its parent directory:

```sh
patch --dry-run --batch --forward --fuzz=0 -p1 < ../CVE-2026-74727-upstream.patch
patch --batch --forward --fuzz=0 -p1 < ../CVE-2026-74727-upstream.patch
make -C /lib/modules/7.0.0-38-generic/build \
  M="$PWD/drivers/net/ovpn" CONFIG_OVPN=m \
  CC=x86_64-linux-gnu-gcc -j1 modules
```

The recorded patch application used zero fuzz with line offsets of -6 and -5. The build returned exit code 0. BTF generation was skipped because `vmlinux` was unavailable. The module vermagic matched `7.0.0-38-generic SMP preempt mod_unload modversions`.

Matching vermagic and a successful build do not establish that a module is safe or that the vulnerability has been fully validated.

## Recorded functional tests

Tests were performed manually on a Hyper-V Ubuntu VM with kernel `7.0.0-38-generic` and Secure Boot disabled. Results are based on operator-supplied terminal output:

- The test module loaded and its build-ID matched the loaded module's build-ID.
- The existing OpenVPN DCO connection reconnected successfully.
- A separate network namespace supported creating and deleting an MP interface.
- A test peer could be created, queried, configured and deleted.
- A modified test CLI changed a test peer's VPN IPv4 address from `192.0.2.2` to `192.0.2.3`; the returned peer state confirmed the change. This was confined to a temporary test namespace and did not change the operational VPN address.
- The reviewed kernel log contained no matching BUG, Oops, KASAN, general protection fault or soft lockup messages. Unsigned out-of-tree module taint messages were present.
- Test namespaces were removed and the distribution module was reloaded after testing. The operational VPN reconnected.

## Deterministic VPN-IP rehash regression test

On 2026-10-06, two standalone test modules executed the actual `ovpn_peer_hash_vpn_ip()` function extracted from the unpatched backup and patched source. Private synthetic objects were kept allocated throughout. After simulating completed removal from the hash tables, the test called the function again under `ovpn->lock`.

| Property | Before patch | After patch |
| --- | --- | --- |
| Active peer is entered in IPv4 and IPv6 tables | PASS | PASS |
| Removed peer remains outside IPv4 and IPv6 tables | FAIL | PASS |
| Occupied IPv4 / IPv6 buckets after rehash of removed peer | 1 / 1 | 0 / 0 |

This is a runtime check of the specific post-removal invariant, not a reproduction of a concurrent deletion race or a use-after-free. The baseline's invariant failure is expected and demonstrates that the test distinguishes the two function versions. Both modules were subsequently unloaded. The operational VPN remained active with its address unchanged. The reviewed log interval contained the test results and no matching BUG, Oops, general protection fault or soft lockup messages.

See [TESTING.md](TESTING.md) for the recorded output, reproduction instructions and limits. The generator is in [tests/prepare-ovpn-rehash-regtest.py](tests/prepare-ovpn-rehash-regtest.py).

## Deterministic transport-endpoint / float regression test

On 2026-10-06, standalone test modules also executed the actual `ovpn_peer_endpoints_update()` function extracted from the unpatched and patched sources, with the production binding helpers. For both IPv4 and IPv6, private synthetic packet headers caused an active peer to float, then caused another endpoint update after its hash entries had been removed while its storage remained allocated.

| Property, for both IPv4 and IPv6 | Before patch | After patch |
| --- | --- | --- |
| Active peer floats and remains in transport table | PASS | PASS |
| Endpoint update is reached after modeled removal | PASS | PASS |
| Removed peer remains outside transport table | FAIL | PASS |
| Occupied transport buckets after removed-peer update | 1 | 0 |

No packets were transmitted, and no real interfaces, VPN peers or addresses were modified. Both test modules were unloaded afterwards; the operational VPN remained active with its address unchanged. The reviewed log interval contained the four test results and no matching BUG, Oops, general protection fault or soft lockup lines.

See [FLOAT-TESTING.md](FLOAT-TESTING.md) and [tests/prepare-ovpn-float-regtest.py](tests/prepare-ovpn-float-regtest.py) for scope, reproduction instructions and recorded results.

## Limits

The concurrent deletion/rehash race was not reproduced. Both modified rehash paths were tested in a deterministic synthetic post-removal state; this does not establish full correctness under real concurrency. No exploit-based regression test, KASAN-enabled run, lockdep-enabled run or sustained concurrency test was performed. The tests do not exercise the complete authenticated network receive path, real production deletion callbacks or every hash-table lookup. The earlier VPN IPv4 CLI test confirmed API behavior only.

This module was not installed persistently or deployed to production. Other OpenVPN kernel vulnerabilities were outside this patch's scope. No binary release is proposed.

## Recovery during a temporary module test

Use an isolated test VM with console access. Stopping a VPN service can disconnect an SSH session. A network namespace shares the host kernel and does not protect the VM from a kernel crash.

Keep the distribution module files unchanged. If the test module was loaded only with `insmod`, stop all services using it, unload it without forcing removal, load the original with `modprobe ovpn`, then restart those services from the console. If unloading fails, inspect remaining users rather than force unloading. A reboot also returns to the distribution module when no persistent installation was made.

