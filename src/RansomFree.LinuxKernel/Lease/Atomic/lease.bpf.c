// SPDX-License-Identifier: GPL-2.0-only
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "lease_event.h"
char LICENSE[] SEC("license")="GPL";
extern struct file *sq_bpf_get_current_exe_file(void) __ksym;
extern void sq_bpf_put_file(struct file *file) __ksym;
extern int sq_bpf_file_d_path(struct file *file,char *buffer,size_t buffer__sz) __ksym;
extern s64 sq_lease_capture_file(struct file *source,u64 cookie) __ksym;
extern s64 sq_lease_finalize(u64 id,u64 cookie,u64 generation,s64 error,u64 epoch) __ksym;
struct { __uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__type(key,u32);__type(value,struct lease_filter); } lease_config SEC(".maps");
#ifdef SQ_CONTROLLED_V2
struct { __uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,SQ_WATCH_MAX);__uint(map_flags,BPF_F_RDONLY_PROG);__type(key,struct lease_watch_key);__type(value,struct lease_watch_value); } watched_targets SEC(".maps");
#endif
struct { __uint(type,BPF_MAP_TYPE_RINGBUF);__uint(max_entries,1048576); } events SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__type(key,u32);__type(value,u64); } lost SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_TASK_STORAGE);__uint(map_flags,BPF_F_NO_PREALLOC);__type(key,int);__type(value,struct lease_scratch); } event_scratch SEC(".maps");
// Report-only provenance experiment. No policy is enforced and no whitelist
// match is emitted. mm pointers are private keys, never exported as evidence.
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
SEC("lsm.s/task_alloc")
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
/* Each invocation owns its scalar evidence on the BPF stack. Large path
 * buffers are task-local, claimed with one unique atomic owner token. No
 * scratch pointer is used after a sleepable kfunc without a fresh lookup. */
static __always_inline struct lease_scratch *owned_scratch(struct task_struct *task,u64 owner)
{
 struct lease_scratch *s=bpf_task_storage_get(&event_scratch,task,0,0);
 return s && __sync_val_compare_and_swap(&s->owner,owner,owner)==owner?s:0;
}
static __always_inline void emit_loss(void)
{
 u32 zero=0;u64 *count=bpf_map_lookup_elem(&lost,&zero);
 if(count)__sync_fetch_and_add(count,1);
}
/* Qualification-only BPF LSM, attached first and therefore run AFTER observe
 * on this kernel (trampoline list adds each subsequent program at the head).
 * An earlier nonzero return short-circuits the remaining MODIFY_RETURN hooks.
 * This fixture proves a later denial is not a completed result at observe.
 * The only denial is the exact
 * owned target inode/device while diagnostic mode 10 is explicitly set. */
SEC("lsm/file_open")
int BPF_PROG(sq_test_denial,struct file *target,int ret)
{
#ifndef SQ_CONTROLLED_V2
 u32 zero=0;struct lease_filter *f=bpf_map_lookup_elem(&lease_config,&zero);
 if(ret)return ret;
 if(f && f->epoch && f->mode==10 && BPF_CORE_READ(target,f_inode,i_ino)==f->inode && BPF_CORE_READ(target,f_inode,i_sb,s_dev)==f->device)return -13;
#else
 /* Neutral link retained solely for the already qualified attachment order. */
 (void)target;
#endif
 return ret;
}
SEC("lsm.s/file_open")
int BPF_PROG(observe,struct file *target,int ret)
{
 u32 zero=0;
 struct lease_filter *filter=bpf_map_lookup_elem(&lease_config,&zero);
 struct task_struct *task=bpf_get_current_task_btf();
 struct lease_header h={};
 struct lease_scratch *s;
 struct file *actor;
 if (!filter || !filter->epoch) return ret;
#ifdef SQ_CONTROLLED_V2
 if(filter->mode)return ret;
 struct lease_watch_key target_key={.inode=BPF_CORE_READ(target,f_inode,i_ino),.device=BPF_CORE_READ(target,f_inode,i_sb,s_dev),.reserved=0};
 struct lease_watch_value *watched=bpf_map_lookup_elem(&watched_targets,&target_key);
 if(!watched || watched->reserved || watched->ordinal>=SQ_WATCH_MAX)return ret;
 h.target_inode=target_key.inode;h.target_device=target_key.device;h.target_ordinal=watched->ordinal;
#else
 if (BPF_CORE_READ(target,f_inode,i_ino)!=filter->inode ||
     BPF_CORE_READ(target,f_inode,i_sb,s_dev)!=filter->device) return ret;
#endif
 /* Shared saturating allocator makes both provenance and event tokens unique
  * within this provider epoch, including same-task nested observations. */
 h.cookie=next_generation();h.epoch=filter->epoch;h.mode=filter->mode;
 h.pid_tid=bpf_get_current_pid_tgid();h.prior_result=ret;
 h.task_start_ns=BPF_CORE_READ(task,start_boottime);
 h.process_start_ns=BPF_CORE_READ(task,group_leader,start_boottime);
 h.self_exec_id=BPF_CORE_READ(task,self_exec_id);
 h.actor_path_result=-61;h.target_path_result=-61;h.lease=-61;
 const struct cred *cred=NULL;
 h.credential_error=BPF_CORE_READ_INTO(&cred,task,cred);
 if (!h.credential_error && cred) {
#define READ_CREDENTIAL(field,member,bit) do { int error=BPF_CORE_READ_INTO(&h.field,cred,member.val); if (!error)h.credential_fields|=bit;else if (!h.credential_error)h.credential_error=error; } while(0)
  READ_CREDENTIAL(uid,uid,1);READ_CREDENTIAL(euid,euid,2);READ_CREDENTIAL(fsuid,fsuid,4);
  READ_CREDENTIAL(gid,gid,8);READ_CREDENTIAL(egid,egid,16);READ_CREDENTIAL(fsgid,fsgid,32);
#undef READ_CREDENTIAL
 } else if (!h.credential_error)h.credential_error=-14;
 if (!h.cookie) { h.capture_issue=5;h.lease=-75;goto compact; }
 /* Modes 4..8 are owned-lab fault injection, never a policy verdict. */
 s=h.mode==4?0:bpf_task_storage_get(&event_scratch,task,0,BPF_LOCAL_STORAGE_GET_F_CREATE);
 if (!s) { h.capture_issue=1;h.actor_path_result=-12;h.target_path_result=-12; }
 else if (__sync_val_compare_and_swap(&s->owner,0,h.cookie)!=0) {
  h.capture_issue=2;h.actor_path_result=-16;h.target_path_result=-16;
 } else if (h.mode==5) {
  /* Exercise a second claim without overwriting this simulated outer owner. */
  h.negative_result=__sync_val_compare_and_swap(&s->owner,0,h.cookie+1);
  h.capture_issue=2;h.actor_path_result=-16;h.target_path_result=-16;
 } else {
  _Static_assert(sizeof(s->event)%8==0,"event alignment");
#pragma clang loop unroll(disable)
  for (u32 n=0;n<sizeof(s->event)/8;n++)((volatile u64 *)&s->event)[n]=0;
  h.target_path_result=sq_bpf_file_d_path(target,s->event.target_path,sizeof(s->event.target_path));
  h.target_path_rendered_ns=bpf_ktime_get_ns();
 }
 u64 mm=(u64)BPF_CORE_READ(task,mm);
 h.before=provenance(task,mm,&h.error_before);h.association_error=h.error_before;
 actor=sq_bpf_get_current_exe_file();
#ifndef BAD_NULL
 if (!actor) { h.association_error=-61;goto emit; }
#endif
 if (!h.capture_issue) {
  s=owned_scratch(task,h.cookie);
  if(s) { h.actor_path_result=sq_bpf_file_d_path(actor,s->event.actor_path,sizeof(s->event.actor_path));h.actor_path_rendered_ns=bpf_ktime_get_ns(); }
  else h.capture_issue=3;
 }
 h.actor_inode=BPF_CORE_READ(actor,f_inode,i_ino);
 h.actor_device=BPF_CORE_READ(actor,f_inode,i_sb,s_dev);
 h.actor_size=BPF_CORE_READ(actor,f_inode,i_size);
 h.capture_start_ns=bpf_ktime_get_ns();
 h.reservation=sq_lease_capture_file(actor,h.cookie);
 h.capture_end_ns=bpf_ktime_get_ns();
 if(h.mode==6)bpf_task_storage_delete(&event_scratch,task);
 s=owned_scratch(task,h.cookie);
 if(!s && !h.capture_issue)h.capture_issue=3;
 h.after=provenance(task,mm,&h.error_after);
 if (mm!=(u64)BPF_CORE_READ(task,mm)) { h.after=0;h.error_after=-116; }
 h.association_error=h.error_before?h.error_before:h.error_after;
 if (!h.association_error && (!h.before || h.before!=h.after || (h.after&1) || h.capture_issue==3)) h.association_error=-116;
 if (h.reservation>0) {
  if (h.mode==1) { h.finalize_error=-115;h.lease=h.reservation; }
  else {
   if (h.mode==2) {
    h.negative_result=sq_lease_finalize(h.reservation,h.cookie+1,h.after,h.association_error,h.epoch);
    s=owned_scratch(task,h.cookie);if(!s && !h.capture_issue){h.capture_issue=3;h.association_error=-116;}
   }
   h.finalize_error=sq_lease_finalize(h.reservation,h.cookie,h.after,h.association_error,h.epoch);
   if(h.mode==7)bpf_task_storage_delete(&event_scratch,task);
   /* A changed owner is another invocation's scratch and must not be cleared. */
   if(h.mode==8){s=owned_scratch(task,h.cookie);if(s)__sync_val_compare_and_swap(&s->owner,h.cookie,h.cookie+1);}
   s=owned_scratch(task,h.cookie);if(!s && !h.capture_issue)h.capture_issue=4;
   h.lease=h.finalize_error?h.finalize_error:h.reservation;
   if (h.mode==3) {
    h.negative_result=sq_lease_finalize(h.reservation,h.cookie,h.after,h.association_error,h.epoch);
    s=owned_scratch(task,h.cookie);if(!s && !h.capture_issue)h.capture_issue=4;
   }
  }
 } else h.lease=h.reservation;
#ifndef BAD_RELEASE
 sq_bpf_put_file(actor);
#endif
emit:
 s=owned_scratch(task,h.cookie);
 if(s && !h.capture_issue) {
  s->event.h=h;
  if(bpf_ringbuf_output(&events,&s->event,sizeof(s->event),0))emit_loss();
  __sync_val_compare_and_swap(&s->owner,h.cookie,0);
  return ret;
 }
 if(!h.capture_issue)h.capture_issue=4;
compact:
 /* Scalar event survives scratch failure. Never export stale path bytes or
  * imply that a path is available when only its former length survived. */
 h.actor_path_result=-61;h.target_path_result=-61;
 h.actor_path_rendered_ns=0;h.target_path_rendered_ns=0;
 if(bpf_ringbuf_output(&events,&h,sizeof(h),0))emit_loss();
 s=owned_scratch(task,h.cookie);
 if(s && h.cookie)__sync_val_compare_and_swap(&s->owner,h.cookie,0);
 return ret;
}
