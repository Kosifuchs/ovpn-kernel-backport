# Focused review of peer membership and lifetime

## Scope and evidence

This is a focused static review of operator-supplied excerpts from the patched Ubuntu `linux 7.0.0-38.38` source. It covers the two changed rehash paths, their shown callers, the MP removal path and the shown receive-reference handoff. It is not a complete driver audit, lock-order audit or runtime lifecycle test. The reported line numbers below are specific to that reviewed source tree.

## Membership is checked under the removal lock

`ovpn_peer_remove()` in `peer.c` requires `ovpn->lock`. In MP mode it checks whether `hash_entry_id` is already unhashed, then unlinks the ID, VPN IPv4, VPN IPv6 and transport-address entries. It queues the peer for subsequent socket release and reference drop.

The patched MP branch of `ovpn_peer_endpoints_update()` acquires `ovpn->lock` followed by `peer->lock`. After checking the binding, it checks `hlist_unhashed(&peer->hash_entry_id)` and retains both locks through transport-table rehashing. Its common exit releases `peer->lock` and then `ovpn->lock`.

`ovpn_peer_hash_vpn_ip()` asserts that `ovpn->lock` is held and checks the same ID-membership marker before modifying either VPN-address table. The assertion itself does not acquire the lock. Both shown callers satisfy that requirement:

- The Netlink peer-set path acquires `ovpn->lock` before `ovpn_nl_peer_modify()`, calls the rehash helper while still holding it, and then unlocks and drops its peer reference.
- `ovpn_peer_add_mp()` acquires the lock, inserts the ID entry before calling the VPN-IP helper, and unlocks afterwards. Thus the new guard permits the shown normal addition sequence.

For the reviewed MP removal and rehash paths, the same lock orders the membership decision and table modification: removal first makes the guard skip rehash; rehash first leaves the subsequent removal able to unlink the updated entry. This reasoning depends on the caller retaining a valid peer reference and all relevant removal paths honoring the lock contract. It is not a blanket proof about every driver operation.

## Receive-reference handoff

The shown MP implementations of `ovpn_peer_get_by_id()` and `ovpn_peer_get_by_transp_addr()` perform lookup under `rcu_read_lock()` and call `ovpn_peer_hold()` before returning a peer. That helper uses `kref_get_unless_zero()`.

The UDP receive path uses one of these lookups and transfers the acquired peer reference to `ovpn_recv()`. `ovpn_aead_decrypt()` stores that peer in the packet control block; this assignment does not acquire an additional reference. The post-decryption path keeps the existing reference across the UDP endpoint-update call, including asynchronous crypto completion. On completion, its `drop_nocount` path calls `ovpn_peer_put()`. If no matching key slot exists, `ovpn_recv()` drops the peer reference directly.

The shown endpoint-update call occurs after successful crypto return and packet-ID validation, and within an RCU read-side section protecting the socket lookup. These checks were reviewed in source; they were not exercised by the synthetic float harness. P2P helpers and the complete TCP lifecycle are outside this focused MP finding review.

A retained reference keeps the allocation alive; it does not prove current ID-table membership. This explains why a membership check remains necessary even when the receive path holds a reference.

## Removal and deferred free

The shown `ovpn_peer_del()` acquires `ovpn->lock`, dispatches to the appropriate deletion helper, then calls `unlock_ovpn()`. In MP mode, `ovpn_peer_del_mp()` takes a temporary lookup reference, verifies object identity, calls `ovpn_peer_remove()` and releases the temporary reference.

`unlock_ovpn()` first releases `ovpn->lock`; for each queued peer it then calls `ovpn_socket_release()` and `ovpn_peer_put()`. The latter uses `kref_put()` with `ovpn_peer_release_kref()` as the final-reference callback.

`ovpn_peer_release_kref()` calls `ovpn_peer_release()`. That routine releases crypto state, resets the binding to NULL under `peer->lock`, schedules `ovpn_peer_release_rcu()` with `call_rcu()`, and drops the network-device reference. The RCU callback destroys the destination cache and calls `kfree(peer)`; it does not unlink hash-table entries again.

Thus a removed but reference-held peer may remain allocated during an endpoint update. The guard prevents the reviewed rehash paths from relinking that removed peer. Waiting for an RCU grace period alone would not repair an incorrectly reinserted node.

`ovpn_peer_new()` initializes the peer reference counter, binding, crypto state, lock, statistics, keepalive work and destination cache, and holds the network device. The shown empty-key crypto state initializes both slots to NULL; its release routine checks each slot before dropping a key reference. `ovpn_socket_release()` returns immediately when there is no attached socket. These branches matter when defining the scope of a future harness; empty socket/key slots would not validate real socket or nonempty key teardown.

## Assessment boundary

The reviewed code is consistent with the patch's intended prevention of post-removal rehashing. The deterministic before/after tests, including the later KASAN-enabled float run, support the corresponding state invariant. This is not a runtime proof of peer freeing, absence of all lifetime errors, or correctness under every interleaving.

Outstanding work includes a completed controlled lifecycle harness covering production deletion, final reference drop and the RCU callback, plus separate concurrency and authenticated-network integration validation. No such supplemental harness or results are included in this update.
