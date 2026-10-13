/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SQ_ATOMIC_OPERATION_EVENT_H
#define SQ_ATOMIC_OPERATION_EVENT_H
#define SQ_OPERATION_SCHEMA 1
/* Unpairable diagnostics: root assigns delivery ID, no lease/START authority. */
#define SQ_OPERATION_DIAGNOSTIC_SCHEMA 2
#define SQ_OPERATION_DIAGNOSTIC_STAGE 3
#define SQ_OPERATION_WATCH_MAX 32
enum sq_operation_stage { SQ_OPERATION_ENTRY=1,SQ_OPERATION_PERMISSION_RESULT=2 };
enum sq_operation_hook { SQ_OPERATION_INODE_PERMISSION=1,SQ_OPERATION_FILE_PERMISSION=2,SQ_OPERATION_SCALAR_WRITE=3,SQ_OPERATION_ITER_WRITE=4 };
struct sq_operation_config { __u64 epoch; };
struct sq_operation_watch_key { __u64 inode;__u32 device,reserved; };
struct sq_operation_watch_value { __u32 ordinal,reserved; };
struct sq_operation_key {
 __u64 lease_id,cookie,tgid,tid,process_start_ns,task_start_ns,self_exec_id;
 __u64 association_generation,provider_epoch,actor_device,actor_inode;
 __u64 target_device,target_inode,operation_nonce;
};
struct sq_operation_event {
 __u32 schema_version,struct_size,hook,stage;
 struct sq_operation_key key;
 __u64 observed_ns,entry_ns,actor_size;
 __s64 reservation_result,finalize_result;
 __s32 permission_result,access_mask,identity_error,credential_error;
 __s32 actor_metadata_error,association_error;
 __u32 target_ordinal,credential_fields;
 __u32 uid,euid,fsuid,gid,egid,fsgid;
 __u32 identity_fields,reserved;
};
_Static_assert(sizeof(struct sq_operation_key)==112,"operation full key");
_Static_assert(sizeof(struct sq_operation_event)==232,"fixed operation observation frame");
/* I/O schema 3 keeps the original 232-byte identity/credential frame intact.
 * Availability bits: length=1, offset-before=2, offset-after=4, size-before=8,
 * size-after=16, file-flags=32, rw-flags=64. Error fields retain OS status.
 * Sizes are samples, not proof of an exclusive filesystem transaction. */
struct sq_io_observation {
 __u64 requested_bytes;
 __s64 result,offset_before,offset_after;
 __u64 size_before,size_after;
 __u32 file_flags,rw_flags,fields;
 __s32 collection_error;
 __u64 reserved;
};
struct sq_io_event { struct sq_operation_event observation;struct sq_io_observation io; };
_Static_assert(sizeof(struct sq_io_observation)==72,"I/O extension size");
_Static_assert(sizeof(struct sq_io_event)==304,"completed I/O observation size");
#endif
