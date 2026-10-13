// SPDX-License-Identifier: GPL-2.0-only
/* Candidate operation observations, not a verdict or final syscall result.
 * Never attach until exact verifier, owner, map and lifecycle gates pass. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "atomic_operation_event.h"
char LICENSE[] SEC("license")="GPL";
extern struct file *sq_bpf_get_current_exe_file(void) __ksym;
extern void sq_bpf_put_file(struct file *actor) __ksym;
extern s64 sq_lease_reserve_observed_atomic(struct file *actor,u64 cookie,u64 nonce,u64 target_inode,u64 target_device) __ksym;
extern s64 sq_lease_finalize_atomic(u64 id,u64 cookie,u64 generation,s64 error,u64 epoch) __ksym;
extern s64 sq_lease_abort_atomic(u64 id,u64 cookie,s64 error) __ksym;
extern int sq_actor_copy_active(void) __ksym;
struct {__uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__type(key,u32);__type(value,struct sq_operation_config);} op_config SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,SQ_OPERATION_WATCH_MAX);__uint(map_flags,BPF_F_RDONLY_PROG);__type(key,struct sq_operation_watch_key);__type(value,struct sq_operation_watch_value);} op_targets SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_RINGBUF);__uint(max_entries,1048576);} op_events SEC(".maps");
/* Scalar-read, storage, nested-call, ring, allocator failures. Map misses are
 * unmonitored files, not loss. Root must bind health to an admitted interval. */
struct {__uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,6);__type(key,u32);__type(value,u64);} op_health SEC(".maps");
struct sq_operation_call { u64 depth;u32 entry_ring_submitted,reserved;struct sq_operation_event event;struct sq_io_observation io; };
_Static_assert(sizeof(struct sq_operation_call)==320,"call state layout");
struct {__uint(type,BPF_MAP_TYPE_TASK_STORAGE);__uint(map_flags,BPF_F_NO_PREALLOC);__type(key,int);__type(value,struct sq_operation_call);} inode_calls SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_TASK_STORAGE);__uint(map_flags,BPF_F_NO_PREALLOC);__type(key,int);__type(value,struct sq_operation_call);} file_calls SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_TASK_STORAGE);__uint(map_flags,BPF_F_NO_PREALLOC);__type(key,int);__type(value,struct sq_operation_call);} scalar_calls SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_TASK_STORAGE);__uint(map_flags,BPF_F_NO_PREALLOC);__type(key,int);__type(value,struct sq_operation_call);} iter_calls SEC(".maps");
struct sq_mm_state { struct bpf_spin_lock lock; __u32 padding; __u64 value; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 8192); __type(key, __u64); __type(value, struct sq_mm_state); } mm_provenance SEC(".maps");
struct sq_token { __u64 mm, generation, exec_id; int error; };
struct { __uint(type, BPF_MAP_TYPE_TASK_STORAGE); __uint(map_flags, BPF_F_NO_PREALLOC); __type(key, int); __type(value, struct sq_token); } task_tokens SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, __u64); } generations SEC(".maps");
static __always_inline __u64 next_generation(void)
{
    __u32 zero=0;__u64 *counter=bpf_map_lookup_elem(&generations,&zero);
    if(!counter)return 0;
    // Saturate rather than reuse a token after overflow. Bounded contention
    // failure leaves this exec unknown; it cannot create an eligible token.
    for(int i=0;i<4;i++) {
        __u64 old=*(volatile __u64 *)counter;
        if(old>0xfffffffffffffffcULL)return 0;
        if(__sync_val_compare_and_swap(counter,old,old+2)==old)return old+2;
    }
    return 0;
}
SEC("lsm/task_prctl")
int BPF_PROG(sq_mm_prctl, int option, unsigned long arg2, unsigned long arg3,
             unsigned long arg4, unsigned long arg5, int ret)
{
    // PR_SET_MM=35; EXE_FILE=13; MAP=14, verified against Linux UAPI.
    if(option==35 && (arg2==13 || arg2==14)) {
        struct task_struct *task=bpf_get_current_task_btf();
        __u64 mm=(__u64)BPF_CORE_READ(task,mm);
        struct sq_mm_state *state=bpf_map_lookup_elem(&mm_provenance,&mm);
        if(state){bpf_spin_lock(&state->lock);state->value|=1;bpf_spin_unlock(&state->lock);}
    }
    return ret;
}
SEC("lsm/bprm_committed_creds")
int BPF_PROG(sq_mm_exec, struct linux_binprm *bprm)
{
    struct task_struct *task=bpf_get_current_task_btf();
    __u64 mm=(__u64)BPF_CORE_READ(task,mm);
    struct sq_token *token=bpf_task_storage_get(&task_tokens,task,0,BPF_LOCAL_STORAGE_GET_F_CREATE);
    if(!token)return 0;
    token->generation=0;token->error=-61;
    __u64 epoch=next_generation();
    struct sq_mm_state value={.value=epoch};
    if(!mm || !epoch){token->error=-11;return 0;}
    // Only this ordinary-exec LSM hook can replace a stale address entry.
    // A fresh never-reused generation and lifetime-bound task token are required;
    // a map entry or mm address alone never qualifies an event.
    int inserted=bpf_map_update_elem(&mm_provenance,&mm,&value,BPF_ANY);
    if(inserted){token->error=inserted;return 0;}
    token->mm=mm;token->exec_id=BPF_CORE_READ(task,self_exec_id);token->generation=epoch;token->error=0;
    return 0;
}
static __always_inline __u64 provenance(struct task_struct *task, __u64 mm, int *error)
{
    struct sq_token *token=bpf_task_storage_get(&task_tokens,task,0,0);
    *error=token && token->error?token->error:-61;
    if(!token || !token->generation)return 0;
    *error=-116;
    if(token->mm!=mm || token->exec_id!=BPF_CORE_READ(task,self_exec_id))return 0;
    struct sq_mm_state *state=bpf_map_lookup_elem(&mm_provenance,&mm);
    if(!state){*error=-2;return 0;}
    bpf_spin_lock(&state->lock);__u64 value=state->value;bpf_spin_unlock(&state->lock);
    // Pointer reuse alone can never validate a task: its lifetime-bound token
    // must match the unique generation of that actual mm association.
    if((value&~1ULL)!=token->generation)return 0;
    *error=(value&1)?-117:0;return value;
}
#ifdef SQ_KERNEL61_ATOMIC_ONLY
/* The 6.1 verifier forbids spin locks in sleepable programs. This bounded
 * map/task-storage operation performs no filesystem I/O or sleeping kfunc.
 * Exact-kernel qualification must separately validate the non-sleepable hook.
 */
SEC("lsm/task_alloc")
#else
SEC("lsm.s/task_alloc")
#endif
int BPF_PROG(sq_task_alloc, struct task_struct *child, unsigned long clone_flags, int ret)
{
    struct sq_token *target=bpf_task_storage_get(&task_tokens,child,0,BPF_LOCAL_STORAGE_GET_F_CREATE);
    if(!target)return ret;
    target->generation=0;target->mm=0;target->exec_id=0;target->error=-61;
    if(!(clone_flags&0x100))return ret; // CLONE_VM, Linux UAPI
    struct task_struct *parent=bpf_get_current_task_btf();
    __u64 mm=(__u64)BPF_CORE_READ(parent,mm);
    int error=0;__u64 known=provenance(parent,mm,&error);
    if(!known || (known&1))return ret;
    target->mm=mm;target->exec_id=BPF_CORE_READ(child,self_exec_id);target->generation=known;target->error=0;
    return ret;
}

static __always_inline void health(u32 kind)
{
 u64 *counter=bpf_map_lookup_elem(&op_health,&kind);
 if(counter)__sync_fetch_and_add(counter,1);
}
static __always_inline int output(struct sq_operation_call *call)
{
 if(call->event.hook==SQ_OPERATION_SCALAR_WRITE || call->event.hook==SQ_OPERATION_ITER_WRITE){
  struct sq_io_event *raw=bpf_ringbuf_reserve(&op_events,sizeof(*raw),0);
  if(!raw){health(3);return -28;}
  __builtin_memcpy(&raw->observation,&call->event,sizeof(call->event));
  __builtin_memcpy(&raw->io,&call->io,sizeof(call->io));bpf_ringbuf_submit(raw,0);return 0;
 }
 struct sq_operation_event *raw=bpf_ringbuf_reserve(&op_events,sizeof(*raw),0);
 if(!raw){health(3);return -28;}
 __builtin_memcpy(raw,&call->event,sizeof(*raw));bpf_ringbuf_submit(raw,0);return 0;
}
static __always_inline void io_error(struct sq_io_observation *io,int error)
{if(error && !io->collection_error)io->collection_error=error;}
static __always_inline struct sq_operation_call *call_state(struct task_struct *task,u32 hook,bool create)
{
 if(hook==SQ_OPERATION_SCALAR_WRITE)return bpf_task_storage_get(&scalar_calls,task,0,create?BPF_LOCAL_STORAGE_GET_F_CREATE:0);
 if(hook==SQ_OPERATION_ITER_WRITE)return bpf_task_storage_get(&iter_calls,task,0,create?BPF_LOCAL_STORAGE_GET_F_CREATE:0);
 if(hook==SQ_OPERATION_INODE_PERMISSION)return bpf_task_storage_get(&inode_calls,task,0,create?BPF_LOCAL_STORAGE_GET_F_CREATE:0);
 return bpf_task_storage_get(&file_calls,task,0,create?BPF_LOCAL_STORAGE_GET_F_CREATE:0);
}
static __always_inline int enter(struct inode *target,int mask,u32 hook,struct file *file,u64 requested,loff_t *pos,u32 rw_flags,int requested_error)
{
 if(sq_actor_copy_active())return 0;
 u32 zero=0;struct sq_operation_config *config=bpf_map_lookup_elem(&op_config,&zero);
 if(!config || !config->epoch)return 0;
 struct task_struct *task=bpf_get_current_task_btf();
 struct sq_operation_call *call=call_state(task,hook,false);
 /* Track every nested check, including misses, so its exit cannot consume
  * an outer monitored event. Never overwrite a live outer invocation. */
 if(call && call->depth==~0ULL){
  health(2);
  if(call->event.key.lease_id)sq_lease_abort_atomic(call->event.key.lease_id,call->event.key.cookie,-75);
  call->depth=1;call->entry_ring_submitted=0;call->event.stage=0;return 0;
 }
 if(call && call->depth)call->depth++;
 struct sq_operation_watch_key key={};
 int issue=BPF_CORE_READ_INTO(&key.inode,target,i_ino);
 if(!issue)issue=BPF_CORE_READ_INTO(&key.device,target,i_sb,s_dev);
 if(issue){health(0);return 0;}
 /* A successfully read zero inode cannot match a qualified nonzero watch
  * identity. It is an unmonitored inode, not a scalar-read failure. */
 if(!key.inode)return 0;
 struct sq_operation_watch_value *watched=bpf_map_lookup_elem(&op_targets,&key);
 if(!watched)return 0;
 if(watched->reserved || watched->ordinal>=SQ_OPERATION_WATCH_MAX){health(0);return 0;}
 /* Unmonitored nested checks do not lose monitored evidence. Keep their
  * depth so their exits cannot consume the outer invocation. A watched
  * nested operation remains an explicit collection failure, never healthy. */
 if(call && call->depth>1){health(2);return 0;}
 /* Allocate only after an exact watch match. Keep existing outer depth for
  * nested misses, but do not allocate/free task storage for unrelated I/O
  * or count its allocation pressure as a missed monitored operation. */
 if(!call || !call->depth){
  call=call_state(task,hook,true);
  if(!call){health(1);return 0;}
  call->depth=1;
 }
 call->entry_ring_submitted=0;
 __builtin_memset(&call->event,0,sizeof(call->event));__builtin_memset(&call->io,0,sizeof(call->io));
 struct sq_operation_event *e=&call->event;
 e->schema_version=hook>=3?3:SQ_OPERATION_SCHEMA;e->struct_size=hook>=3?sizeof(struct sq_io_event):sizeof(*e);e->hook=hook;e->stage=SQ_OPERATION_ENTRY;
 e->entry_ns=bpf_ktime_get_ns();e->observed_ns=e->entry_ns;e->access_mask=mask;
 if(hook>=3){
  struct sq_io_observation *io=&call->io;
  if(!requested_error){io->requested_bytes=requested;io->fields=1;}else io_error(io,requested_error);
  int r=pos?bpf_probe_read_kernel(&io->offset_before,sizeof(io->offset_before),pos):-61;
  if(!r)io->fields|=2;else io_error(io,r);
  r=BPF_CORE_READ_INTO(&io->size_before,target,i_size);
  if(!r)io->fields|=8;else io_error(io,r);
  r=BPF_CORE_READ_INTO(&io->file_flags,file,f_flags);
  if(!r)io->fields|=32;else io_error(io,r);
  io->rw_flags=rw_flags;io->fields|=64;
 }
 e->target_ordinal=watched->ordinal;e->key.target_inode=key.inode;e->key.target_device=key.device;
 e->key.provider_epoch=config->epoch;e->key.cookie=next_generation();e->key.operation_nonce=next_generation();
 u64 ids=bpf_get_current_pid_tgid();e->key.tgid=ids>>32;e->key.tid=(u32)ids;
#define ID_READ(field,member,bit) do { int r=BPF_CORE_READ_INTO(&e->key.field,task,member);if(!r)e->identity_fields|=bit;else if(!e->identity_error)e->identity_error=r; } while(0)
 issue=BPF_CORE_READ_INTO(&e->key.process_start_ns,task,group_leader,start_boottime);
 if(!issue)e->identity_fields|=1;else e->identity_error=issue;
 ID_READ(task_start_ns,start_boottime,2);ID_READ(self_exec_id,self_exec_id,4);
#undef ID_READ
 const struct cred *cred=0;e->credential_error=BPF_CORE_READ_INTO(&cred,task,cred);
 if(!e->credential_error && cred){
#define CRED_READ(field,bit) do {int r=BPF_CORE_READ_INTO(&e->field,cred,field.val);if(!r && e->field!=0xffffffffU)e->credential_fields|=bit;else if(!e->credential_error)e->credential_error=r?r:-22;}while(0)
  CRED_READ(uid,1);CRED_READ(euid,2);CRED_READ(fsuid,4);CRED_READ(gid,8);CRED_READ(egid,16);CRED_READ(fsgid,32);
#undef CRED_READ
 }else if(!e->credential_error)e->credential_error=-14;
 u64 mm=0;issue=BPF_CORE_READ_INTO(&mm,task,mm);
 int before_error=issue;u64 before=issue?0:provenance(task,mm,&before_error);
 e->association_error=before_error;e->key.association_generation=before;
 e->reservation_result=-61;e->finalize_result=-61;e->actor_metadata_error=-61;
 if(!e->key.cookie || !e->key.operation_nonce){
  health(4);e->reservation_result=-75;
  /* Keep collected process/credential/target facts, but no operation key.
   * Distinct schema/stage cannot be paired, suppressed or authorize START. */
  e->schema_version=hook>=3?4:SQ_OPERATION_DIAGNOSTIC_SCHEMA;e->stage=SQ_OPERATION_DIAGNOSTIC_STAGE;
  e->key.cookie=0;e->key.operation_nonce=0;e->key.association_generation=0;
  goto emit;
 }
 struct file *actor=sq_bpf_get_current_exe_file();
 if(!actor){e->reservation_result=-2;goto emit;}
 e->actor_metadata_error=BPF_CORE_READ_INTO(&e->key.actor_inode,actor,f_inode,i_ino);
 u32 actor_device=0;
 if(!e->actor_metadata_error)e->actor_metadata_error=BPF_CORE_READ_INTO(&actor_device,actor,f_inode,i_sb,s_dev);
 e->key.actor_device=actor_device;
 if(!e->actor_metadata_error)e->actor_metadata_error=BPF_CORE_READ_INTO(&e->actor_size,actor,f_inode,i_size);
 e->reservation_result=sq_lease_reserve_observed_atomic(actor,e->key.cookie,e->key.operation_nonce,key.inode,key.device);
 sq_bpf_put_file(actor);
 if(e->reservation_result>0){
  e->key.lease_id=e->reservation_result;
  int after_error=0;u64 after=provenance(task,mm,&after_error);
  if(before_error || after_error || !before || before!=after || (after&1))e->association_error=before_error?before_error:(after_error?after_error:-116);
  e->finalize_result=sq_lease_finalize_atomic(e->key.lease_id,e->key.cookie,after,e->association_error,e->key.provider_epoch);
  e->key.association_generation=after;
 }
emit:
 if(output(call)){
  if(e->key.lease_id)sq_lease_abort_atomic(e->key.lease_id,e->key.cookie,-28);
  call->entry_ring_submitted=0;e->stage=0;
 }else if((e->schema_version==SQ_OPERATION_SCHEMA || e->schema_version==3) && e->stage==SQ_OPERATION_ENTRY){
  call->entry_ring_submitted=1;
 }else{call->entry_ring_submitted=0;e->stage=0;}
 return 0;
}
static __always_inline int leave(s64 result,u32 hook,struct file *file,loff_t *pos)
{
 if(sq_actor_copy_active())return 0;
 struct task_struct *task=bpf_get_current_task_btf();struct sq_operation_call *call=call_state(task,hook,false);
 if(!call || !call->depth)return 0;
 call->depth--;
 if(call->depth)return 0;
 if(call->entry_ring_submitted && call->event.stage==SQ_OPERATION_ENTRY &&
    (call->event.schema_version==SQ_OPERATION_SCHEMA || call->event.schema_version==3)){
  call->event.stage=SQ_OPERATION_PERMISSION_RESULT;call->event.observed_ns=bpf_ktime_get_ns();
  if(hook>=3){
   struct sq_io_observation *io=&call->io;io->result=result;
   int r=pos?bpf_probe_read_kernel(&io->offset_after,sizeof(io->offset_after),pos):-61;
   if(!r)io->fields|=4;else io_error(io,r);
   r=BPF_CORE_READ_INTO(&io->size_after,file,f_inode,i_size);
   if(!r)io->fields|=16;else io_error(io,r);
  }else call->event.permission_result=(int)result;
  output(call);
 }
 /* Do not retain idle call state on long-lived unmonitored tasks. No access
  * to call/event after delete, including failed-delete health reporting. */
 int deleted;
 if(hook==SQ_OPERATION_SCALAR_WRITE)deleted=bpf_task_storage_delete(&scalar_calls,task);
 else if(hook==SQ_OPERATION_ITER_WRITE)deleted=bpf_task_storage_delete(&iter_calls,task);
 else deleted=hook==SQ_OPERATION_INODE_PERMISSION?bpf_task_storage_delete(&inode_calls,task):bpf_task_storage_delete(&file_calls,task);
 if(deleted)health(5);
 return 0;
}
/* Exact-profile compiler switch only; qualification must check target BTF.
 * Linux 6.1 uses a user namespace here, later kernels use mnt_idmap.
 */
#ifdef SQ_KERNEL61_ATOMIC_ONLY
#define SQ_PERMISSION_OWNER struct user_namespace
#else
#define SQ_PERMISSION_OWNER struct mnt_idmap
#endif
SEC("fentry/inode_permission")
int BPF_PROG(sq_inode_enter,SQ_PERMISSION_OWNER *idmap,struct inode *target,int mask)
{return enter(target,mask,SQ_OPERATION_INODE_PERMISSION,0,0,0,0,0);}
SEC("fexit/inode_permission")
int BPF_PROG(sq_inode_leave,SQ_PERMISSION_OWNER *idmap,struct inode *target,int mask,int result)
{return leave(result,SQ_OPERATION_INODE_PERMISSION,0,0);}
SEC("fentry/security_file_permission")
int BPF_PROG(sq_file_enter,struct file *target,int mask)
{
 struct inode *inode=0;int error=BPF_CORE_READ_INTO(&inode,target,f_inode);
 if(error){health(0);return enter(0,mask,SQ_OPERATION_FILE_PERMISSION,0,0,0,0,0);}
 return enter(inode,mask,SQ_OPERATION_FILE_PERMISSION,0,0,0,0,0);
}
SEC("fexit/security_file_permission")
int BPF_PROG(sq_file_leave,struct file *target,int mask,int result)
{return leave(result,SQ_OPERATION_FILE_PERMISSION,0,0);}

/* The return hooks report actual synchronous VFS bytes/errors, never open intent.
 * Pending -EIOCBQUEUED (-529) remains pending; it is not a failed or completed write.
 * Async io_uring paths which bypass these functions need separate completion hooks. */
SEC("fentry/vfs_write")
int BPF_PROG(sq_write_enter,struct file *file,const char *buffer,size_t count,loff_t *pos)
{return enter(BPF_CORE_READ(file,f_inode),2,SQ_OPERATION_SCALAR_WRITE,file,count,pos,0,0);}
SEC("fexit/vfs_write")
int BPF_PROG(sq_write_leave,struct file *file,const char *buffer,size_t count,loff_t *pos,ssize_t result)
{return leave(result,SQ_OPERATION_SCALAR_WRITE,file,pos);}
/* writev/pwritev do not pass through vfs_iter_write. Observe their shared
 * synchronous iterator helper once; type=WRITE (1) excludes reads. Exact
 * prototype is checked against the installed kernel BTF before attachment. */
SEC("fentry/do_iter_readv_writev")
int BPF_PROG(sq_iter_write_enter,struct file *file,struct iov_iter *iter,loff_t *pos,int type,rwf_t flags)
{if(type!=1)return 0;u64 count=0;int error=BPF_CORE_READ_INTO(&count,iter,count);return enter(BPF_CORE_READ(file,f_inode),2,SQ_OPERATION_ITER_WRITE,file,count,pos,flags,error);}
SEC("fexit/do_iter_readv_writev")
int BPF_PROG(sq_iter_write_leave,struct file *file,struct iov_iter *iter,loff_t *pos,int type,rwf_t flags,ssize_t result)
{return type==1?leave(result,SQ_OPERATION_ITER_WRITE,file,pos):0;}
