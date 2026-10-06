# KASAN-enabled execution of the synthetic float test

## Evidence and scope

Recorded on 2026-10-06, local time Europe/Berlin. Results, configuration and hashes below are based on operator-supplied terminal output. The kernel binaries and test modules are not included in this repository. Exact binary reproducibility is not asserted.

The existing generator [tests/prepare-ovpn-float-regtest.py](tests/prepare-ovpn-float-regtest.py) and the synthetic procedure in [FLOAT-TESTING.md](FLOAT-TESTING.md) were reused. The test still directly unlinks private peer entries while retaining allocated peer storage. Running it with KASAN does not turn this modeled removal into a production deletion, concurrent race reproduction or use-after-free reproduction.

The VM also runs an administrative VPN. Private test objects and unregistered network devices do not isolate it from a kernel crash. Console access and a distribution-kernel fallback were prepared before the test boot.

## Kernel build and installation record

- Source package: reviewed Ubuntu `linux 7.0.0-38.38`, with the recorded upstream patch applied to `drivers/net/ovpn/peer.c`.
- Architecture: x86_64, Hyper-V guest.
- Initial configuration: copied from `/boot/config-7.0.0-38-generic`; SHA-256 `6cb18717c6914d4947489eedf8cb69ac23db3faa8ef9b9f563ff02c346dcd32d`.
- Compiler: `x86_64-linux-gnu-gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0`.
- Linker reported by the booted kernel: GNU ld, binutils 2.46.
- Custom release: `7.0.14-ovpn-kasan`. This is the source-derived custom release, distinct from Ubuntu's distribution ABI name `7.0.0-38-generic`.
- Full `bzImage modules` build: exit code 0, using one build process.
- Staged `modules_install`: exit code 0 after restoring the executable permission on Ubuntu's `debian/scripts/sign-module`. The earlier staging attempt emitted `Permission denied`; it was repeated, not treated as successful signing evidence. Individual module signature validity was not separately checked.
- Installed boot image: approximately 21 MB; System.map approximately 11 MB. Staged kernel/module files approximately 1.1 GB.
- `update-initramfs -c -k 7.0.14-ovpn-kasan`: exit code 0; initramfs approximately 62 MB. Its listing included `hv_vmbus.ko`, `hv_storvsc.ko`, `hv_netvsc.ko` and the ext4 root configuration.
- GRUB configuration passed `grub-script-check`; distribution kernel 38 remained the explicit default. The test kernel was manually selected through the Hyper-V console.

Reported configuration:

```text
CONFIG_LOCALVERSION="-ovpn-kasan"
CONFIG_BLK_DEV_INITRD=y
CONFIG_HYPERV_STORAGE=m
CONFIG_OVPN=m
CONFIG_HYPERV_NET=m
CONFIG_HYPERV=y
CONFIG_EXT4_FS=y
CONFIG_DEBUG_INFO_NONE=y
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y
CONFIG_KASAN_OUTLINE=y
CONFIG_STACKTRACE=y
```

The initial configuration step also disabled local-version auto-detection and BTF/debug-info options, and cleared the distribution trusted/revocation certificate paths. Absence of debug information limits source-line diagnosis. KCSAN and lockdep were not intentionally enabled; this run does not provide their evidence.

The build was interrupted by exhaustion of the Windows host volume containing the expanding VHDX. Free guest filesystem space did not prevent this host-side failure. Host storage was freed and the incremental build resumed to the recorded successful exit. Subsequent guest boot and test success do not constitute a complete filesystem-integrity audit.

## Test-module build

Both existing generated test directories were rebuilt against the full custom kernel source/build tree, rather than the distribution kernel headers:

```sh
# From the already configured and successfully built custom kernel source root:
(
    set -e
    for variant in before after; do
        make -C "$PWD" M="$PWD/../ovpn-float-regtest/$variant" \
          CC=x86_64-linux-gnu-gcc -j1 modules
    done
)
```

The recorded invocation used fail-fast handling and returned `Testbuild-Exitcode: 0`. Both transferred modules reported:

```text
7.0.14-ovpn-kasan SMP preempt mod_unload modversions
```

The export filenames gained `_kasan`; their internal module names remained `ovpn_float_before` and `ovpn_float_after`. The existing distribution-header builds were not used for this run.

## Recorded artifact hashes

Hashes matched between export and test host. These binaries are not distributed here; they must not be treated as binaries for distribution kernel 38.

| Artifact | Recorded SHA-256 |
| --- | --- |
| Private kernel/module transport archive `ovpn-kasan-7.0.14.tar.gz` | `022738d422573edf8ffe6761b9c5883096cc631c16f242237ff5f0840c1bb3d5` |
| `ovpn_float_before_kasan.ko` | `b340c1e9e5bf4081122cd38d5b5370e35122ea34e980974192c6a011753e0992` |
| `ovpn_float_after_kasan.ko` | `aad00dfea530f335af42d060cfc8ea2a13d53e9b11245dc8a785244e5a274a9a` |

The archive hash records transfer integrity, not trust, security certification or reproducibility. No individual kernel-image checksum was supplied.

## Recorded runtime results

The VM booted `7.0.14-ovpn-kasan` at approximately 21:28. Its administrative VPN service reported `active`. Before testing, the supplied filtered boot log showed the custom kernel version and command line, with no matching BUG/Oops error lines.

```text
21:32:09 ovpn-float-regtest before IPv4: active=PASS endpoint-update=PASS removed-invariant=FAIL occupied=1 expected=PASS
21:32:09 ovpn-float-regtest before IPv6: active=PASS endpoint-update=PASS removed-invariant=FAIL occupied=1 expected=PASS
21:32:35 ovpn-float-regtest after IPv4: active=PASS endpoint-update=PASS removed-invariant=PASS occupied=0 expected=PASS
21:32:35 ovpn-float-regtest after IPv6: active=PASS endpoint-update=PASS removed-invariant=PASS occupied=0 expected=PASS
```

The supplied bounded log search covered test results and `BUG:`, `KASAN:`, `Oops:` and `general protection fault`; it returned the four result lines above and no matching error lines. Baseline `expected=PASS` means the known incorrect reinsertion was observed. Only the patched variant passed the removed-peer invariant.

The final `lsmod` query showed no float test modules. The administrative VPN service was active. Available guest memory was approximately 628 MiB, with 24 MiB swap used. The VM was subsequently rebooted into `7.0.0-38-generic`; that release and the active VPN service were confirmed in terminal output. Test-kernel files remain installed for future work.

## Interpretation and remaining work

This run provides additional evidence that the synthetic active-peer, endpoint-update and removed-peer checks behave as expected on a kernel configured with Generic KASAN. No detected memory error appeared in the supplied filtered interval.

It does **not** prove that the original use-after-free was reproduced before the patch or eliminated after it. Peer storage stayed allocated until the harness's cleanup; the harness did not execute the production peer deletion/refcount/RCU-free sequence. There was no deliberately invalid access to demonstrate KASAN detection, no full authenticated traffic integration test, no sustained concurrency test and no completed supplemental lifecycle test. The VPN-IP-only test has not been rerun under KASAN.

Keep these limits attached to any public summary. Describe this as a **KASAN-enabled synthetic regression run**, not complete KASAN validation of the vulnerability.
