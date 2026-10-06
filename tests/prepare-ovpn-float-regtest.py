#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Generate standalone synthetic float invariant tests; does not load modules."""
from pathlib import Path
import hashlib
import shutil

root = Path.cwd()
driver = root / "drivers/net/ovpn"
patch = root.parent / "CVE-2026-74727-upstream.patch"
expected = "baf0962c60b182776a86e040d2ec5b35eea2737c2e2eb6f17f87eb7d2fe47b24"
if hashlib.sha256(patch.read_bytes()).hexdigest() != expected:
    raise SystemExit("Unexpected patch checksum.")
before = (root.parent / "peer.c.vor-CVE-2026-74727").read_text()
after = (driver / "peer.c").read_text()

def function(text, signature):
    if text.count(signature) != 1:
        raise SystemExit(f"Unexpected signature count: {signature}")
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

def macros(text):
    lines = text.splitlines()
    result = []
    for name in ("ovpn_get_hash_slot", "ovpn_get_hash_head"):
        starts = [i for i, line in enumerate(lines)
                  if line.startswith("#define " + name + "(")]
        if len(starts) != 1:
            raise SystemExit(f"Unexpected macro count: {name}")
        i = starts[0]
        block = [lines[i]]
        while block[-1].rstrip().endswith("\\"):
            i += 1
            if i >= len(lines):
                raise SystemExit("Incomplete macro.")
            block.append(lines[i])
        result.append("\n".join(block))
    return "\n".join(result)

float_signature = "void ovpn_peer_endpoints_update(struct ovpn_peer *peer, struct sk_buff *skb)"
reset_signature = "int ovpn_peer_reset_sockaddr(struct ovpn_peer *peer,"
before_fn = function(before, float_signature)
after_fn = function(after, float_signature)
reset = function(after, reset_signature)
hash_macros = macros(after)
if reset != function(before, reset_signature) or hash_macros != macros(before):
    raise SystemExit("Supporting functions/macros differ; manual review required.")
if "hlist_unhashed(&peer->hash_entry_id)" in before_fn:
    raise SystemExit("Baseline already contains the float guard.")
if "hlist_unhashed(&peer->hash_entry_id)" not in after_fn:
    raise SystemExit("Patched float function lacks the guard.")
destination = root.parent / "ovpn-float-regtest"
if destination.exists():
    raise SystemExit(f"Refusing to overwrite {destination}")

prefix = r'''// SPDX-License-Identifier: GPL-2.0-only
/* Synthetic state test only. No interface registration or packet transmission.
 * Functions/macros are extracted unchanged from reviewed Ubuntu kernel source.
 * Original authorship is retained in peer-source.c.txt and copied headers.
 */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/list_nulls.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/rculist.h>
#include <linux/rculist_nulls.h>
#include <linux/etherdevice.h>
#include <linux/udp.h>
#include <net/ip6_route.h>
#include <net/ipv6.h>
#include "ovpnpriv.h"
#include "peer.h"
#include "bind.h"
'''

suffix = r'''
static unsigned int occupied(struct ovpn_peer_collection *tables)
{
        unsigned int result = 0;
        size_t i;
        for (i = 0; i < ARRAY_SIZE(tables->by_transp_addr); i++)
                if (!hlist_nulls_empty(&tables->by_transp_addr[i]))
                        result++;
        return result;
}

static void address(struct sockaddr_storage *ss, bool v6, u8 last, u16 port)
{
        memset(ss, 0, sizeof(*ss));
        if (v6) {
                struct sockaddr_in6 *sa = (struct sockaddr_in6 *)ss;
                sa->sin6_family = AF_INET6;
                sa->sin6_port = htons(port);
                sa->sin6_addr.s6_addr[0] = 0x20;
                sa->sin6_addr.s6_addr[1] = 0x01;
                sa->sin6_addr.s6_addr[2] = 0x0d;
                sa->sin6_addr.s6_addr[3] = 0xb8;
                sa->sin6_addr.s6_addr[15] = last;
        } else {
                struct sockaddr_in *sa = (struct sockaddr_in *)ss;
                sa->sin_family = AF_INET;
                sa->sin_port = htons(port);
                sa->sin_addr.s_addr = htonl(0xc0000200 | last);
        }
}

static void packet(struct sk_buff *skb, bool v6, u8 last, u16 port)
{
        struct sockaddr_storage remote, local;
        struct udphdr *udp;
        address(&remote, v6, last, port);
        address(&local, v6, 1, 1194);
        memset(skb->data, 0, skb->len);
        skb_reset_network_header(skb);
        if (v6) {
                struct ipv6hdr *ip = (struct ipv6hdr *)skb->data;
                ip->version = 6;
                ip->nexthdr = IPPROTO_UDP;
                ip->payload_len = htons(sizeof(*udp));
                ip->saddr = ((struct sockaddr_in6 *)&remote)->sin6_addr;
                ip->daddr = ((struct sockaddr_in6 *)&local)->sin6_addr;
                skb_set_transport_header(skb, sizeof(*ip));
                skb->protocol = htons(ETH_P_IPV6);
        } else {
                struct iphdr *ip = (struct iphdr *)skb->data;
                ip->version = 4;
                ip->ihl = 5;
                ip->protocol = IPPROTO_UDP;
                ip->tot_len = htons(skb->len);
                ip->saddr = ((struct sockaddr_in *)&remote)->sin_addr.s_addr;
                ip->daddr = ((struct sockaddr_in *)&local)->sin_addr.s_addr;
                skb_set_transport_header(skb, sizeof(*ip));
                skb->protocol = htons(ETH_P_IP);
        }
        udp = udp_hdr(skb);
        udp->source = htons(port);
        udp->dest = htons(1194);
        udp->len = htons(sizeof(*udp));
        /* No checksum/authentication or network transmission is attempted. */
}

static bool endpoint_matches(struct ovpn_peer *peer, struct sk_buff *skb)
{
        bool result;
        spin_lock_bh(&peer->lock);
        result = ovpn_bind_skb_src_match(
                rcu_dereference_protected(peer->bind,
                                           lockdep_is_held(&peer->lock)), skb);
        spin_unlock_bh(&peer->lock);
        return result;
}

static int run_family(bool v6)
{
        struct ovpn_priv *ovpn;
        struct ovpn_peer *peer = NULL;
        struct sk_buff *skb = NULL;
        struct ovpn_bind *bind = NULL;
        struct sockaddr_storage ss;
        unsigned int count;
        bool active_ok, endpoint_ok, removed_ok, expected_ok;
        bool cache_ready = false;
        size_t i, length;
        int ret = -ENOMEM;

        ovpn = kzalloc(sizeof(*ovpn), GFP_KERNEL);
        if (!ovpn)
                return ret;
        peer = kzalloc(sizeof(*peer), GFP_KERNEL);
        ovpn->peers = kzalloc(sizeof(*ovpn->peers), GFP_KERNEL);
        ovpn->dev = alloc_netdev(0, "ovpn-ft%d", NET_NAME_UNKNOWN, ether_setup);
        if (!peer || !ovpn->peers || !ovpn->dev)
                goto cleanup;
        spin_lock_init(&ovpn->lock);
        spin_lock_init(&peer->lock);
        ovpn->mode = OVPN_MODE_MP;
        peer->ovpn = ovpn;
        peer->id = 1;
        ret = dst_cache_init(&peer->dst_cache, GFP_KERNEL);
        if (ret)
                goto cleanup;
        cache_ready = true;
        ret = -ENOMEM;
        for (i = 0; i < ARRAY_SIZE(ovpn->peers->by_id); i++) {
                INIT_HLIST_HEAD(&ovpn->peers->by_id[i]);
                INIT_HLIST_NULLS_HEAD(&ovpn->peers->by_vpn_addr4[i], i);
                INIT_HLIST_NULLS_HEAD(&ovpn->peers->by_vpn_addr6[i], i);
                INIT_HLIST_NULLS_HEAD(&ovpn->peers->by_transp_addr[i], i);
        }
        address(&ss, v6, 10, 1111);
        bind = ovpn_bind_from_sockaddr(&ss);
        if (IS_ERR(bind)) {
                ret = PTR_ERR(bind);
                bind = NULL;
                goto cleanup;
        }
        RCU_INIT_POINTER(peer->bind, bind);
        length = (v6 ? sizeof(struct ipv6hdr) : sizeof(struct iphdr)) +
                 sizeof(struct udphdr);
        skb = alloc_skb(length, GFP_KERNEL);
        if (!skb)
                goto detach;
        skb_put(skb, length);

        spin_lock_bh(&ovpn->lock);
        hlist_add_head_rcu(&peer->hash_entry_id, &ovpn->peers->by_id[0]);
        hlist_nulls_add_head_rcu(&peer->hash_entry_transp_addr,
                ovpn_get_hash_head(ovpn->peers->by_transp_addr, &bind->remote,
                                  v6 ? sizeof(struct sockaddr_in6) :
                                       sizeof(struct sockaddr_in)));
        spin_unlock_bh(&ovpn->lock);

        packet(skb, v6, 11, 2222);
        local_bh_disable();
        rcu_read_lock();
        ovpn_peer_endpoints_update(peer, skb);
        rcu_read_unlock();
        local_bh_enable();
        active_ok = endpoint_matches(peer, skb) && occupied(ovpn->peers) == 1 &&
                    !hlist_nulls_unhashed(&peer->hash_entry_transp_addr);

        /* Model completed removal while keeping storage allocated. */
        spin_lock_bh(&ovpn->lock);
        hlist_del_init_rcu(&peer->hash_entry_id);
        hlist_nulls_del_init_rcu(&peer->hash_entry_transp_addr);
        spin_unlock_bh(&ovpn->lock);
        packet(skb, v6, 12, 3333);
        local_bh_disable();
        rcu_read_lock();
        ovpn_peer_endpoints_update(peer, skb);
        rcu_read_unlock();
        local_bh_enable();
        endpoint_ok = endpoint_matches(peer, skb);
        count = occupied(ovpn->peers);
        removed_ok = count == 0 &&
                     hlist_nulls_unhashed(&peer->hash_entry_transp_addr);
        expected_ok = EXPECT_GUARD ? removed_ok :
                      (count == 1 &&
                       !hlist_nulls_unhashed(&peer->hash_entry_transp_addr));
        pr_info("ovpn-float-regtest %s IPv%u: active=%s endpoint-update=%s removed-invariant=%s occupied=%u expected=%s\n",
                TEST_VARIANT, v6 ? 6 : 4, active_ok ? "PASS" : "FAIL",
                endpoint_ok ? "PASS" : "FAIL", removed_ok ? "PASS" : "FAIL",
                count, expected_ok ? "PASS" : "FAIL");
        ret = active_ok && endpoint_ok && expected_ok ? 0 : -EINVAL;
        spin_lock_bh(&ovpn->lock);
        hlist_nulls_del_init_rcu(&peer->hash_entry_transp_addr);
        spin_unlock_bh(&ovpn->lock);
detach:
        /* Old bindings were queued by the production bind reset function.
         * The final binding is detached under the same lock before freeing.
         */
        spin_lock_bh(&peer->lock);
        ovpn_bind_reset(peer, NULL);
        spin_unlock_bh(&peer->lock);
        rcu_barrier();
cleanup:
        kfree_skb(skb);
        if (cache_ready)
                dst_cache_destroy(&peer->dst_cache);
        if (ovpn->dev)
                free_netdev(ovpn->dev);
        kfree(ovpn->peers);
        kfree(peer);
        kfree(ovpn);
        return ret;
}

static int __init float_init(void)
{
        int ret = run_family(false);
        if (ret)
                return ret;
        return run_family(true);
}
static void __exit float_exit(void) { }
module_init(float_init);
module_exit(float_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Synthetic OpenVPN transport float invariant test");
'''

for variant, source, body, guard in (
    ("before", before, before_fn, 0), ("after", after, after_fn, 1)
):
    directory = destination / variant
    directory.mkdir(parents=True)
    for header in driver.glob("*.h"):
        shutil.copyfile(header, directory / header.name)
    shutil.copyfile(driver / "bind.c", directory / "bind.c")
    name = "ovpn_float_" + variant
    (directory / "Makefile").write_text(
        f"obj-m := {name}.o\n{name}-y := float_test.o bind.o\n"
    )
    (directory / "peer-source.c.txt").write_text(source)
    (directory / "float_test.c").write_text(
        prefix + f'\n#define EXPECT_GUARD {guard}\n#define TEST_VARIANT "{variant}"\n'
        + reset + "\n\n" + hash_macros + "\n\n" + body + "\n" + suffix
    )
    print(f"Generated {directory / 'float_test.c'}")
print("No build or module load performed. Synthetic float state test only.")
