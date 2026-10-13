/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SQ_LEASE_H
#define SQ_LEASE_H
#include <linux/types.h>
#include <linux/ioctl.h>
enum sq_state { SQ_PENDING=1, SQ_COPYING=2, SQ_COMPLETE=3, SQ_FAILED=4, SQ_EXPIRED_DRAINING=5, SQ_PROVISIONAL=6 };
struct sq_meta {
 __u64 id, cookie, started_ns, finished_ns, deadline_ns;
 __u64 size, inode, device, bytes, tgid, tid, process_start_ns;
 __u64 task_start_ns, self_exec_id, association_generation, provider_epoch;
 __u32 state;
 __s32 error;
 __u32 write_lease, metadata_changed;
 __u32 association_state; /* 0 pending, 1 verified association, 2 unavailable */
 __s32 association_error;
 __u32 schema_version, struct_size;
};
#define SQ_STATUS _IOWR('Q', 1, struct sq_meta)
#define SQ_SELECT _IOW('Q', 2, __u64)
#define SQ_DROP _IOW('Q', 3, __u64)
#endif
