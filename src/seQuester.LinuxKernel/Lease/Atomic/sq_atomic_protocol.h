/* SPDX-License-Identifier: GPL-2.0-only
 * Candidate-only, separately negotiated atomic protocol. Existing schema2
 * and its ioctl numbers remain untouched. This declares no deployed support.
 */
#ifndef SQ_ATOMIC_PROTOCOL_H
#define SQ_ATOMIC_PROTOCOL_H
#include <linux/types.h>
#include <linux/ioctl.h>
#define SQ_ATOMIC_ABI_VERSION 1
enum sq_atomic_state {
 SQ_A_EMPTY=0, SQ_A_RESERVING=1, SQ_A_RESERVED_RAW_PENDING=2,
 SQ_A_FINALIZED_RAW_PENDING=3, SQ_A_COPY_QUEUED=4, SQ_A_COPYING=5,
 SQ_A_ABORT_DRAINING=6, SQ_A_COMPLETE=7, SQ_A_UNAVAILABLE=8
};
/* Lifetime, provenance, executable object, target object and operation nonce.
 * No path or PID-only key can authorize a copy. A slot's id is never reused.
 * The operation nonce belongs to the observed operation, not a filesystem path.
 */
struct sq_atomic_key {
 __u64 lease_id, cookie, tgid, tid, process_start_ns, task_start_ns;
 __u64 self_exec_id, association_generation, provider_epoch;
 __u64 actor_device, actor_inode, target_device, target_inode, operation_nonce;
};
struct sq_atomic_request {
 __u32 abi_version, struct_size;
 struct sq_atomic_key key;
 __u64 raw_receipt_low, raw_receipt_high;
};
/* This response does not replace sq_meta or confer schema2 completion.
 * Error is a raw negative errno where available, never invented success.
 */
struct sq_atomic_status {
 struct sq_atomic_request authorization;
 __u32 state;
 __s32 error;
 __u64 started_ns, deadline_ns, finished_ns, size, bytes;
 __u32 f2_owned, write_exclusion_owned;
};
#define SQ_ATOMIC_STATUS _IOWR('Q', 16, struct sq_atomic_status)
#define SQ_ATOMIC_START _IOW('Q', 17, struct sq_atomic_request)
#define SQ_ATOMIC_DROP _IOW('Q', 18, struct sq_atomic_request)
#define SQ_ATOMIC_SELECT _IOW('Q', 19, struct sq_atomic_request)
/* Root-only enumeration for orphan reservations/source-loss cleanup. */
#define SQ_ATOMIC_NEXT _IOWR('Q', 20, struct sq_atomic_status)
/* Pins one managed-admitted source epoch to this exclusive controller. */
#define SQ_ATOMIC_REGISTER _IOW('Q', 21, struct sq_atomic_request)

/* Field comparison avoids undefined padding becoming authorization input. */
static inline int sq_atomic_key_equal(const struct sq_atomic_key *a,
                                      const struct sq_atomic_key *b)
{
 return a->lease_id==b->lease_id && a->cookie==b->cookie &&
  a->tgid==b->tgid && a->tid==b->tid &&
  a->process_start_ns==b->process_start_ns &&
  a->task_start_ns==b->task_start_ns && a->self_exec_id==b->self_exec_id &&
  a->association_generation==b->association_generation &&
  a->provider_epoch==b->provider_epoch &&
  a->actor_device==b->actor_device && a->actor_inode==b->actor_inode &&
  a->target_device==b->target_device && a->target_inode==b->target_inode &&
  a->operation_nonce==b->operation_nonce;
}
static inline int sq_atomic_request_valid(const struct sq_atomic_request *r)
{
 return r->abi_version==SQ_ATOMIC_ABI_VERSION &&
  r->struct_size==sizeof(*r) && r->key.lease_id && r->key.cookie &&
  r->key.tgid && r->key.tid && r->key.process_start_ns &&
  r->key.task_start_ns && r->key.self_exec_id && r->key.association_generation &&
  !(r->key.association_generation&1) && r->key.provider_epoch &&
  r->key.actor_inode && r->key.target_inode && r->key.operation_nonce &&
  (r->raw_receipt_low || r->raw_receipt_high);
}
#endif
