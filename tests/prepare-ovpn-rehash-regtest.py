#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Generate standalone kernel modules testing an isolated rehash invariant.

Does not load modules, alter the original source, or reproduce a live race.
Run from the reviewed Ubuntu kernel source root.
"""
from pathlib import Path
import hashlib
import shutil

root = Path.cwd()
driver = root / "drivers/net/ovpn"
before_file = root.parent / "peer.c.vor-CVE-2026-74727"
patch_file = root.parent / "CVE-2026-74727-upstream.patch"
expected = "baf0962c60b182776a86e040d2ec5b35eea2737c2e2eb6f17f87eb7d2fe47b24"
if hashlib.sha256(patch_file.read_bytes()).hexdigest() != expected:
    raise SystemExit("Unexpected patch checksum; nothing generated.")
before = before_file.read_text()
after = (driver / "peer.c").read_text()

def extract_function(text):
    signature = "void ovpn_peer_hash_vpn_ip(struct ovpn_peer *peer)"
    if text.count(signature) != 1:
        raise SystemExit("Expected exactly one rehash function.")
    start = text.index(signature)
    opening = text.index("{", start)
    depth = 0
    for i in range(opening, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    raise SystemExit("Incomplete function.")

def extract_macros(text):
    result = []
    lines = text.splitlines()
    for name in ("ovpn_get_hash_slot", "ovpn_get_hash_head"):
        starts = [i for i, line in enumerate(lines)
                  if line.startswith("#define " + name + "(")]
        if len(starts) != 1:
            raise SystemExit(f"Missing macro: {name}")
        i = starts[0]
        block = [lines[i]]
        while block[-1].rstrip().endswith("\\"):
            i += 1
            if i >= len(lines):
                raise SystemExit(f"Incomplete macro: {name}")
            block.append(lines[i])
        result.append("\n".join(block))
    return "\n".join(result)

before_fn, after_fn = extract_function(before), extract_function(after)
if "hlist_unhashed(&peer->hash_entry_id)" in before_fn:
    raise SystemExit("Backup already contains the guard.")
if "hlist_unhashed(&peer->hash_entry_id)" not in after_fn:
    raise SystemExit("Patched source lacks the guard.")
macros = extract_macros(after)
if extract_macros(before) != macros:
    raise SystemExit("Hash macros differ between sources.")

destination = root.parent / "ovpn-rehash-regtest"
if destination.exists():
    raise SystemExit(f"Refusing to overwrite {destination}")

prefix = r'''// SPDX-License-Identifier: GPL-2.0-only
/* Test harness: private synthetic objects, no real netdev or peer lookup.
 * The rehash function and hash macros below are copied verbatim from
 * the operator's reviewed Ubuntu source; original authorship is retained
 * in copied source headers and peer-source.c.txt.
 */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/list_nulls.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/rculist.h>
#include <linux/rculist_nulls.h>
#include <net/ipv6.h>
#include "ovpnpriv.h"
#include "peer.h"
'''

suffix = r'''
static unsigned int occupied(struct hlist_nulls_head *heads, size_t count)
{
        unsigned int result = 0;
        size_t i;
        for (i = 0; i < count; i++)
                if (!hlist_nulls_empty(&heads[i]))
                        result++;
        return result;
}

static int __init regtest_init(void)
{
        struct ovpn_priv *ovpn;
        struct ovpn_peer *peer;
        unsigned int n4, n6;
        bool active_ok, removed_ok, expected_ok;
        size_t i;
        int ret = -EINVAL;

        ovpn = kzalloc(sizeof(*ovpn), GFP_KERNEL);
        if (!ovpn)
                return -ENOMEM;
        peer = kzalloc(sizeof(*peer), GFP_KERNEL);
        if (!peer) {
                kfree(ovpn);
                return -ENOMEM;
        }
        ovpn->peers = kzalloc(sizeof(*ovpn->peers), GFP_KERNEL);
        if (!ovpn->peers) {
                kfree(peer);
                kfree(ovpn);
                return -ENOMEM;
        }
        spin_lock_init(&ovpn->lock);
        ovpn->mode = OVPN_MODE_MP;
        peer->ovpn = ovpn;
        /* Documentation address 192.0.2.2 and IPv6 loopback are never used
         * on an interface, socket or route: only as private hash keys.
         */
        peer->vpn_addrs.ipv4.s_addr = htonl(0xc0000202);
        peer->vpn_addrs.ipv6 = in6addr_loopback;
        INIT_HLIST_NODE(&peer->hash_entry_id);
        /* kzalloc has already initialized each nulls node's next and
         * pprev to NULL, the required initial unhashed state.
         */
        for (i = 0; i < ARRAY_SIZE(ovpn->peers->by_id); i++) {
                INIT_HLIST_HEAD(&ovpn->peers->by_id[i]);
                INIT_HLIST_NULLS_HEAD(&ovpn->peers->by_vpn_addr4[i], i);
                INIT_HLIST_NULLS_HEAD(&ovpn->peers->by_vpn_addr6[i], i);
                INIT_HLIST_NULLS_HEAD(&ovpn->peers->by_transp_addr[i], i);
        }

        spin_lock_bh(&ovpn->lock);
        /* Membership sentinel only: no ID lookup is performed in this test. */
        hlist_add_head_rcu(&peer->hash_entry_id, &ovpn->peers->by_id[0]);
        ovpn_peer_hash_vpn_ip(peer);
        n4 = occupied(ovpn->peers->by_vpn_addr4,
                      ARRAY_SIZE(ovpn->peers->by_vpn_addr4));
        n6 = occupied(ovpn->peers->by_vpn_addr6,
                      ARRAY_SIZE(ovpn->peers->by_vpn_addr6));
        active_ok = n4 == 1 && n6 == 1 &&
                    !hlist_nulls_unhashed(&peer->hash_entry_addr4) &&
                    !hlist_nulls_unhashed(&peer->hash_entry_addr6);

        /* Model the completed unhash operation, retaining allocated memory.
         * No real peer deletion, release callback, notification or UAF occurs.
         */
        hlist_del_init_rcu(&peer->hash_entry_id);
        hlist_nulls_del_init_rcu(&peer->hash_entry_addr4);
        hlist_nulls_del_init_rcu(&peer->hash_entry_addr6);
        hlist_nulls_del_init_rcu(&peer->hash_entry_transp_addr);
        ovpn_peer_hash_vpn_ip(peer);
        n4 = occupied(ovpn->peers->by_vpn_addr4,
                      ARRAY_SIZE(ovpn->peers->by_vpn_addr4));
        n6 = occupied(ovpn->peers->by_vpn_addr6,
                      ARRAY_SIZE(ovpn->peers->by_vpn_addr6));
        removed_ok = n4 == 0 && n6 == 0 &&
                     hlist_nulls_unhashed(&peer->hash_entry_addr4) &&
                     hlist_nulls_unhashed(&peer->hash_entry_addr6);
        expected_ok = EXPECT_GUARD ? removed_ok :
                      (n4 == 1 && n6 == 1 &&
                       !hlist_nulls_unhashed(&peer->hash_entry_addr4) &&
                       !hlist_nulls_unhashed(&peer->hash_entry_addr6));

        /* Unlink any baseline reinsertions before freeing private objects. */
        hlist_nulls_del_init_rcu(&peer->hash_entry_addr4);
        hlist_nulls_del_init_rcu(&peer->hash_entry_addr6);
        spin_unlock_bh(&ovpn->lock);
        pr_info("ovpn-regtest %s: active=%s removed-invariant=%s occupied4=%u occupied6=%u expected=%s\n",
                TEST_VARIANT, active_ok ? "PASS" : "FAIL",
                removed_ok ? "PASS" : "FAIL", n4, n6,
                expected_ok ? "PASS" : "FAIL");
        if (active_ok && expected_ok)
                ret = 0;
        /* There are no external readers, but wait before releasing storage. */
        synchronize_rcu();
        kfree(ovpn->peers);
        kfree(peer);
        kfree(ovpn);
        return ret;
}

static void __exit regtest_exit(void) { }
module_init(regtest_init);
module_exit(regtest_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Isolated OpenVPN VPN-IP rehash invariant regression test");
'''

for variant, function, source, guard in (
    ("before", before_fn, before, 0), ("after", after_fn, after, 1)
):
    directory = destination / variant
    directory.mkdir(parents=True)
    for header in driver.glob("*.h"):
        shutil.copyfile(header, directory / header.name)
    name = "ovpn_regtest_" + variant
    (directory / "Makefile").write_text(f"obj-m := {name}.o\n")
    (directory / "peer-source.c.txt").write_text(source)
    (directory / (name + ".c")).write_text(
        prefix + f'\n#define EXPECT_GUARD {guard}\n#define TEST_VARIANT "{variant}"\n'
        + macros + "\n\n" + function + "\n" + suffix
    )
    print(f"Generated {directory / (name + '.c')}")
print("No build or module load performed. This tests only a synthetic state invariant.")
