/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SQ_ATOMIC_START_H
#define SQ_ATOMIC_START_H
#include <linux/errno.h>
#include "sq_atomic_protocol.h"
/* Caller must hold the native slot state lock and act on the returned state:
 * 0: publish copy work, 1: exact retransmission (do not queue again),
 * negative: no copy authorization; ABORT_DRAINING needs cleanup work.
 * now and active_provider_epoch must come from native-owned state under the
 * lock, never from the ioctl request. Provider epoch must not be reused.
 * This helper neither proves raw durability nor releases any references.
 */
static inline int sq_atomic_accept_start(struct sq_atomic_status *s,
                                        const struct sq_atomic_request *r,
                                        __u64 now,__u64 active_provider_epoch)
{
 if (!sq_atomic_request_valid(r)) return -EINVAL;
 if (!active_provider_epoch) return -ENOTCONN;
 if (s->authorization.key.provider_epoch!=active_provider_epoch) return -ESTALE;
 if (s->authorization.abi_version!=SQ_ATOMIC_ABI_VERSION ||
     s->authorization.struct_size!=sizeof(*r)) return -EPROTO;
 if (!sq_atomic_key_equal(&s->authorization.key,&r->key)) return -ESTALE;
 switch(s->state) {
 case SQ_A_COPY_QUEUED:case SQ_A_COPYING:case SQ_A_COMPLETE:
  return s->authorization.raw_receipt_low==r->raw_receipt_low &&
   s->authorization.raw_receipt_high==r->raw_receipt_high ? 1 : -ESTALE;
 case SQ_A_RESERVING:case SQ_A_RESERVED_RAW_PENDING:return -EAGAIN;
 case SQ_A_ABORT_DRAINING:case SQ_A_UNAVAILABLE:return s->error<0?s->error:-ECANCELED;
 case SQ_A_FINALIZED_RAW_PENDING:break;
 default:return -EPROTO;
 }
 if (s->authorization.raw_receipt_low || s->authorization.raw_receipt_high)
  return -EPROTO;
 if (!s->deadline_ns || now>=s->deadline_ns) {
  s->state=SQ_A_ABORT_DRAINING;s->error=-ETIMEDOUT;return -ETIMEDOUT;
 }
 if (!s->f2_owned || !s->write_exclusion_owned) return -EPROTO;
 s->authorization.raw_receipt_low=r->raw_receipt_low;
 s->authorization.raw_receipt_high=r->raw_receipt_high;
 s->state=SQ_A_COPY_QUEUED;
 return 0;
}
#endif
