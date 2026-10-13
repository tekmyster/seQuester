/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SQ_LEASE_EVENT_H
#define SQ_LEASE_EVENT_H
/* vmlinux supplies these types to BPF; linux/types.h supplies them to user space. */
struct lease_filter { __u64 inode, epoch; __u32 device, mode; };
#ifdef SQ_CONTROLLED_V2
#define SQ_WATCH_MAX 32
struct lease_watch_key { __u64 inode; __u32 device, reserved; };
struct lease_watch_value { __u32 ordinal, reserved; };
_Static_assert(sizeof(struct lease_watch_key)==16,"canonical watch identity key size");
_Static_assert(sizeof(struct lease_watch_value)==8,"canonical watch ordinal size");
#endif
struct lease_header {
 __u64 cookie, epoch, pid_tid, task_start_ns, process_start_ns, self_exec_id;
 __u64 before, after, actor_inode, actor_size;
 __u64 capture_start_ns, capture_end_ns;
 __s64 reservation, lease, finalize_error, negative_result;
 __u32 actor_device, uid, euid, fsuid, gid, egid, fsgid, mode;
 __s32 error_before, error_after, association_error, prior_result;
 __s32 actor_path_result, target_path_result, credential_error;
 __u32 credential_fields;
 __u64 actor_path_rendered_ns, target_path_rendered_ns;
 __u32 capture_issue, reserved;
#ifdef SQ_CONTROLLED_V2
 __u64 target_inode;
 __u32 target_device, target_ordinal;
#endif
};
struct lease_event {
 struct lease_header h;
 char actor_path[4096], target_path[4096];
};
struct lease_scratch { __u64 owner; struct lease_event event; };
#endif
