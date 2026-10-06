# OpenVPN kernel module backport review

Documentation of a local build and functional test of the upstream fix associated with CVE-2026-74727, against Ubuntu kernel source package `linux 7.0.0-38.38` on x86_64.

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

## Limits

The deletion/rehash race was not reproduced. No exploit-based regression test, KASAN-enabled run, lockdep-enabled run or sustained concurrency test was performed. Functional tests do not prove that the race is fixed under all conditions. The VPN IPv4 test confirmed the API behavior, not independently the correctness of every hash-table lookup.

This module was not installed persistently or deployed to production. Other OpenVPN kernel vulnerabilities were outside this patch's scope. No binary release is proposed.

## Recovery during a temporary module test

Use an isolated test VM with console access. Stopping a VPN service can disconnect an SSH session. A network namespace shares the host kernel and does not protect the VM from a kernel crash.

Keep the distribution module files unchanged. If the test module was loaded only with `insmod`, stop all services using it, unload it without forcing removal, load the original with `modprobe ovpn`, then restart those services from the console. If unloading fails, inspect remaining users rather than force unloading. A reboot also returns to the distribution module when no persistent installation was made.

