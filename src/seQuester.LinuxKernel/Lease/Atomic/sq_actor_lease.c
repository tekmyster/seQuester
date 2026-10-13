// SPDX-License-Identifier: GPL-2.0-only
/* Isolated qualification prototype. Never enables a whitelist decision.
 * Admission: four <=4 MiB regular ext4 images, one root-owned controller.
 * Synchronous filesystem reads cannot be forcibly cancelled. Expired work
 * drains with its source reference/write exclusion intact; no late publish.
 */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/capability.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/magic.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/rcupdate.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include "sq_lease.h"
#include "sq_atomic_start.h"
#include "sq_kernel61_compat.h"

#define SQ_SLOTS 4
#define SQ_MAX_BYTES (4 * 1024 * 1024)
#define SQ_BUDGET_NS (2ULL * NSEC_PER_SEC)
/* Atomic root intake includes durable journal and cold managed enrichment.
 * Four slots / four MiB remain fixed; retention is bounded to ten seconds. */
#define SQ_ATOMIC_BUDGET_NS (10ULL * NSEC_PER_SEC)
/* Fixed four-slot retention protects the entry-observed executable while raw
 * evidence is durably admitted. Copy work has its own ten-second budget. */
#define SQ_ATOMIC_RETENTION_NS (60ULL * NSEC_PER_SEC)
struct sq_entry {
 struct delayed_work work;
 struct file *source;
 void *blob;
 struct sq_meta meta;
 struct timespec64 mtime, ctime;
 bool used, cancel;
 bool atomic_route, module_held, dropping, cleanup_queued;
 struct completion reservation_done;
 struct work_struct cleanup_work;
 struct task_struct *copy_task;
 struct sq_atomic_status atomic;
};
struct sq_control { u64 selected; };
static struct sq_entry entries[SQ_SLOTS];
static DEFINE_SPINLOCK(entries_lock);
static DEFINE_MUTEX(control_lock);
static struct workqueue_struct *queue;
static bool controller;
static u64 next_id,active_provider_epoch;
static void atomic_cleanup_actor(struct work_struct *work);
static struct delayed_work provisional_reaper;
static bool stopping;
#ifdef SQ_LEASE_QUALIFICATION
/* Fault injection is compiled only into this isolated research artifact. */
static bool test_queue_failure;
module_param(test_queue_failure,bool,0600);
static unsigned int test_publish_delay_ms, test_capture_delay_ms, test_drop_delay_ms;
static int bounded_delay_set(const char *value,const struct kernel_param *parameter)
{
 unsigned int parsed;
 int error=kstrtouint(value,0,&parsed);
 if (error) return error;
 if (parsed>3000) return -ERANGE;
 WRITE_ONCE(*(unsigned int *)parameter->arg,parsed);
 return 0;
}
static const struct kernel_param_ops delay_ops={.set=bounded_delay_set,.get=param_get_uint};
module_param_cb(test_publish_delay_ms,&delay_ops,&test_publish_delay_ms,0600);
module_param_cb(test_capture_delay_ms,&delay_ops,&test_capture_delay_ms,0600);
module_param_cb(test_drop_delay_ms,&delay_ops,&test_drop_delay_ms,0600);
#endif

static struct sq_entry *find_entry(u64 id)
{
 int n;
 for (n=0;n<SQ_SLOTS;n++)
  if (entries[n].used && entries[n].meta.id==id) return &entries[n];
 return NULL;
}

static void copy_actor(struct work_struct *work)
{
 unsigned long sq_irq_flags;
 struct sq_entry *entry=container_of(to_delayed_work(work),struct sq_entry,work);
 struct file *source=entry->source;
 struct inode *inode=file_inode(source);
 struct timespec64 mt,ct;
 loff_t offset=0;
 void *blob=NULL;
 int error=0;
 ssize_t got;
 u64 finished;
 spin_lock_irqsave(&entries_lock,sq_irq_flags);
 entry->copy_task=current;
 if(entry->atomic_route){
  if(entry->atomic.state!=SQ_A_COPY_QUEUED || entry->cancel){
   spin_unlock_irqrestore(&entries_lock,sq_irq_flags);error=-ECANCELED;goto done;
  }
  entry->atomic.state=SQ_A_COPYING;
 }
 entry->meta.state=SQ_COPYING;
 spin_unlock_irqrestore(&entries_lock,sq_irq_flags);
 if (ktime_get_ns()>=entry->meta.deadline_ns) { error=-ETIMEDOUT; goto done; }
 blob=kvmalloc(entry->meta.size,GFP_KERNEL);
 if (!blob) { error=-ENOMEM; goto done; }
 while (offset<entry->meta.size) {
  if (READ_ONCE(entry->cancel)) { error=-ECANCELED; break; }
  if (ktime_get_ns()>=entry->meta.deadline_ns) { error=-ETIMEDOUT; break; }
  got=kernel_read(source,blob+offset,min_t(u64,65536,entry->meta.size-offset),&offset);
  if (got<=0) { error=got<0?got:-EIO; break; }
  spin_lock_irqsave(&entries_lock,sq_irq_flags);
  entry->meta.bytes=offset;
  if(entry->atomic_route)entry->atomic.bytes=offset;
  spin_unlock_irqrestore(&entries_lock,sq_irq_flags);
 }
 mt=inode_get_mtime(inode);ct=inode_get_ctime(inode);
 /* Rename may change ctime without changing bytes. The referenced ext4
  * object and held write exclusion bind the copy across that path change. */
 spin_lock_irqsave(&entries_lock,sq_irq_flags);
 entry->meta.metadata_changed=!timespec64_equal(&ct,&entry->ctime);
 spin_unlock_irqrestore(&entries_lock,sq_irq_flags);
 if (!error && (i_size_read(inode)!=entry->meta.size ||
     !timespec64_equal(&mt,&entry->mtime)))
  error=-ESTALE;
done:
 /* Retain the write exclusion until all kernel_read calls have returned. */
 spin_lock_irqsave(&entries_lock,sq_irq_flags);
 entry->source=NULL;
 spin_unlock_irqrestore(&entries_lock,sq_irq_flags);
 allow_write_access(source);fput(source);
#ifdef SQ_LEASE_QUALIFICATION
 if (READ_ONCE(test_publish_delay_ms)) msleep(READ_ONCE(test_publish_delay_ms));
#endif
 spin_lock_irqsave(&entries_lock,sq_irq_flags);
 /* One timestamp defines completion. An observer-declared expiry is sticky. */
 finished=ktime_get_ns();
 if (READ_ONCE(entry->cancel)) error=-ECANCELED;
 if (entry->meta.state==SQ_EXPIRED_DRAINING || finished>=entry->meta.deadline_ns) error=-ETIMEDOUT;
 entry->meta.finished_ns=finished;
 entry->meta.error=error;
 entry->meta.state=error?SQ_FAILED:SQ_COMPLETE;entry->meta.write_lease=0;
 entry->copy_task=NULL;
 if(entry->atomic_route){
  entry->atomic.finished_ns=finished;
  entry->atomic.error=error;entry->atomic.state=error?SQ_A_UNAVAILABLE:SQ_A_COMPLETE;
  entry->atomic.f2_owned=0;entry->atomic.write_exclusion_owned=0;
 }
 if (!error) { entry->blob=blob;blob=NULL; }
 spin_unlock_irqrestore(&entries_lock,sq_irq_flags);
 kvfree(blob);
}

__bpf_kfunc_start_defs();

/* Exact Ubuntu 6.8/header-qualified compatibility provider. The mm and file
 * each have their own reference; never retain an unreferenced exe_file.
 * F1 belongs to BPF. sq_lease_capture_file takes a separate F2 before return.
 */
__bpf_kfunc struct file *sq_bpf_get_current_exe_file(void)
{
 struct mm_struct *mm;
 struct file *file;
 mm=get_task_mm(current);
 if (!mm) return NULL;
 rcu_read_lock();
#ifdef SQ_KERNEL61_ATOMIC_ONLY
 /* The 6.1 API increments a supplied file, unlike the later pointer-slot API.
  * RCU protects the observed slot until the independent F1 reference exists.
  */
 file=rcu_dereference(mm->exe_file);
 if(file && !get_file_rcu(file))file=NULL;
#else
 file=get_file_rcu(&mm->exe_file);
#endif
 rcu_read_unlock();
 mmput_async(mm);
 return file;
}

__bpf_kfunc void sq_bpf_put_file(struct file *file)
{
 fput(file);
}

/* Task-root-relative path bytes, matching the existing evidence contract.
 * The 6.8 verifier receives a zero-offset trusted file pointer. Its
 * live f_path is resolved synchronously here; no derived pointer escapes.
 */
__bpf_kfunc int sq_bpf_file_d_path(struct file *file,char *buffer,size_t buffer__sz)
{
 char *resolved;
 size_t length;
 if (!buffer__sz || buffer__sz>INT_MAX) return -EINVAL;
 resolved=d_path(&file->f_path,buffer,buffer__sz);
 if (IS_ERR(resolved)) return PTR_ERR(resolved);
 length=buffer+buffer__sz-resolved;
 memmove(buffer,resolved,length);
 return length;
}

__bpf_kfunc s64 sq_lease_capture_file(struct file *source,u64 cookie)
{
 unsigned long sq_irq_flags;
 struct inode *inode=file_inode(source);
 struct sq_entry *entry=NULL;
 s64 result;
 loff_t size;
 int n,error;
 /* Deliberately narrow native proof. No remote, FUSE, memfd or target copies. */
 if (!S_ISREG(inode->i_mode) || inode->i_sb->s_magic!=EXT4_SUPER_MAGIC)
  return -EOPNOTSUPP;
 if ((source->f_mode&(FMODE_READ|FMODE_CAN_READ))!=(FMODE_READ|FMODE_CAN_READ)) return -EBADF;
 if (i_size_read(inode)<=0 || i_size_read(inode)>SQ_MAX_BYTES) return -EFBIG;
 spin_lock_irqsave(&entries_lock,sq_irq_flags);
 if (!controller) { result=-ENOTCONN;goto out; }
 if (next_id==S64_MAX) { result=-EOVERFLOW;goto out; }
 for (n=0;n<SQ_SLOTS;n++) if (!entries[n].used) { entry=&entries[n];break; }
 if (!entry) { result=-ENOSPC;goto out; }
 if (!try_module_get(THIS_MODULE)) { result=-ENODEV;goto out; }
 get_file(source);
 error=deny_write_access(source);
 if (error) { fput(source);module_put(THIS_MODULE);result=error;goto out; }
 /* The old mm association can lose its write exclusion before our handoff.
  * Recheck the resource bound while our own exclusion is actually held. */
 size=i_size_read(inode);
 if (size<=0 || size>SQ_MAX_BYTES || !(source->f_mode&FMODE_CAN_READ)) {
  allow_write_access(source);fput(source);module_put(THIS_MODULE);result=size<=0 || size>SQ_MAX_BYTES?-EFBIG:-EBADF;goto out;
 }
 memset(&entry->meta,0,sizeof(entry->meta));
 entry->used=true;entry->cancel=false;entry->blob=NULL;entry->source=source;
 entry->atomic_route=false;entry->module_held=true;entry->dropping=false;entry->copy_task=NULL;
 entry->meta.id=++next_id;entry->meta.cookie=cookie;entry->meta.started_ns=ktime_get_ns();
 entry->meta.deadline_ns=entry->meta.started_ns+SQ_BUDGET_NS;
 entry->meta.size=size;entry->meta.inode=inode->i_ino;entry->meta.device=inode->i_sb->s_dev;
 entry->meta.tgid=task_tgid_nr(current);entry->meta.tid=task_pid_nr(current);entry->meta.process_start_ns=current->group_leader->start_boottime;
 entry->meta.task_start_ns=current->start_boottime;
 entry->meta.self_exec_id=current->self_exec_id;
 entry->meta.schema_version=2;entry->meta.struct_size=sizeof(entry->meta);
 entry->meta.state=SQ_PROVISIONAL;entry->meta.write_lease=1;
 entry->mtime=inode_get_mtime(inode);entry->ctime=inode_get_ctime(inode);
 result=entry->meta.id;
out:
 spin_unlock_irqrestore(&entries_lock,sq_irq_flags);
#ifdef SQ_LEASE_QUALIFICATION
 /* Native race fixture only: let another shared-mm task attempt reassignment
  * between the two BPF provenance snapshots. Never included by default. */
 if (result>0 && READ_ONCE(test_capture_delay_ms)) msleep(READ_ONCE(test_capture_delay_ms));
#endif
 return result;
}

__bpf_kfunc s64 sq_lease_finalize(u64 id,u64 cookie,u64 generation,s64 association_error,u64 provider_epoch)
{
 unsigned long sq_irq_flags;
 struct sq_entry *entry;
 struct file *release=NULL;
 bool queued=false,put=false;
 s64 result=0;
 spin_lock_irqsave(&entries_lock,sq_irq_flags);
 entry=find_entry(id);
 if (!entry) { result=-ENOENT;goto out; }
 if(entry->atomic_route){result=-EOPNOTSUPP;goto out;}
 if (entry->meta.cookie!=cookie || entry->meta.tgid!=task_tgid_nr(current) ||
     entry->meta.tid!=task_pid_nr(current) ||
     entry->meta.task_start_ns!=current->start_boottime ||
     entry->meta.process_start_ns!=current->group_leader->start_boottime ||
     entry->meta.self_exec_id!=current->self_exec_id) { result=-ESTALE;goto out; }
 if (entry->meta.state!=SQ_PROVISIONAL || entry->cancel) { result=-EALREADY;goto out; }
 if (!controller) { result=-ENOTCONN;goto out; }
 if (ktime_get_ns()>=entry->meta.deadline_ns) { result=-ETIMEDOUT;goto abandon; }
 if (!association_error && (!generation || (generation&1) || !provider_epoch)) association_error=-EINVAL;
 if (association_error>0 || association_error < -4095) association_error=-EINVAL;
 entry->meta.association_generation=generation;entry->meta.provider_epoch=provider_epoch;
 entry->meta.association_error=association_error;
 entry->meta.association_state=association_error?2:1;
 entry->meta.state=SQ_PENDING;
#ifdef SQ_LEASE_QUALIFICATION
 if (!READ_ONCE(test_queue_failure))
#endif
  queued=queue_delayed_work(queue,&entry->work,msecs_to_jiffies(500));
 if (queued) goto out;
 result=-EIO;
abandon:
 /* Detach before releasing outside the mutex. The work was never queued. */
 release=entry->source;entry->source=NULL;entry->used=false;entry->module_held=false;put=true;
out:
 spin_unlock_irqrestore(&entries_lock,sq_irq_flags);
 if (release) { allow_write_access(release);fput(release); }
 if (put) module_put(THIS_MODULE);
 return result;
}
#include "sq_atomic_native.h"
__bpf_kfunc_end_defs();

/* Ubuntu 6.8 uses the qualified BTF_SET8 kernel API. Newer kernels expose
 * BTF_KFUNCS_START/END; retain their native definitions when present. */
#ifndef BTF_KFUNCS_START
#define BTF_KFUNCS_START(name) BTF_SET8_START(name)
#define BTF_KFUNCS_END(name) BTF_SET8_END(name)
#endif
BTF_KFUNCS_START(sq_kfunc_ids)
BTF_ID_FLAGS(func,sq_bpf_get_current_exe_file,KF_ACQUIRE | KF_TRUSTED_ARGS | KF_RET_NULL)
BTF_ID_FLAGS(func,sq_bpf_put_file,KF_RELEASE)
#ifndef SQ_KERNEL61_ATOMIC_ONLY
BTF_ID_FLAGS(func,sq_bpf_file_d_path,KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func,sq_lease_capture_file,KF_TRUSTED_ARGS | KF_SLEEPABLE)
BTF_ID_FLAGS(func,sq_lease_finalize,KF_SLEEPABLE)
BTF_ID_FLAGS(func,sq_lease_capture_file_atomic,KF_TRUSTED_ARGS)
#endif
BTF_ID_FLAGS(func,sq_lease_finalize_atomic)
BTF_ID_FLAGS(func,sq_lease_reserve_observed_atomic,KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func,sq_lease_abort_atomic)
BTF_ID_FLAGS(func,sq_actor_copy_active)
BTF_KFUNCS_END(sq_kfunc_ids)
#ifndef SQ_KERNEL61_ATOMIC_ONLY
/* LSM and fentry/fexit share the kernel's tracing hook. Register once;
 * restrict tracing to the new atomic primitives and explicit F1 lifetime. */
BTF_ID_LIST(sq_id_sq_bpf_get_current_exe_file)
BTF_ID(func,sq_bpf_get_current_exe_file)
BTF_ID_LIST(sq_id_sq_bpf_put_file)
BTF_ID(func,sq_bpf_put_file)
BTF_ID_LIST(sq_id_sq_bpf_file_d_path)
BTF_ID(func,sq_bpf_file_d_path)
BTF_ID_LIST(sq_id_sq_lease_capture_file)
BTF_ID(func,sq_lease_capture_file)
BTF_ID_LIST(sq_id_sq_lease_finalize)
BTF_ID(func,sq_lease_finalize)
BTF_ID_LIST(sq_id_sq_lease_finalize_atomic)
BTF_ID(func,sq_lease_finalize_atomic)
BTF_ID_LIST(sq_id_sq_lease_reserve_observed_atomic)
BTF_ID(func,sq_lease_reserve_observed_atomic)
BTF_ID_LIST(sq_id_sq_lease_abort_atomic)
BTF_ID(func,sq_lease_abort_atomic)
BTF_ID_LIST(sq_id_sq_actor_copy_active)
BTF_ID(func,sq_actor_copy_active)
static int sq_kfunc_filter(const struct bpf_prog *prog,u32 id)
{
 if(prog->type==BPF_PROG_TYPE_LSM)
  return (id==sq_id_sq_bpf_get_current_exe_file[0] ||
      id==sq_id_sq_bpf_put_file[0] ||
      id==sq_id_sq_bpf_file_d_path[0] ||
      id==sq_id_sq_lease_capture_file[0] ||
      id==sq_id_sq_lease_finalize[0])?0:-EACCES;
 if(prog->type==BPF_PROG_TYPE_TRACING)
  return (id==sq_id_sq_bpf_get_current_exe_file[0] ||
      id==sq_id_sq_bpf_put_file[0] ||
      id==sq_id_sq_lease_finalize_atomic[0] ||
      id==sq_id_sq_lease_reserve_observed_atomic[0] ||
      id==sq_id_sq_lease_abort_atomic[0] ||
      id==sq_id_sq_actor_copy_active[0])?0:-EACCES;
 return -EACCES;
}
static const struct btf_kfunc_id_set sq_kfunc_set={ .owner=THIS_MODULE,.set=&sq_kfunc_ids,.filter=sq_kfunc_filter };
#else
/* No filter member exists in 6.1. The set above contains only the six
 * non-sleepable atomic tracing helpers used by atomic-operation.bpf.c.
 * This is a separate candidate capability; modern profiles keep their filter.
 */
static const struct btf_kfunc_id_set sq_kfunc_set={ .owner=THIS_MODULE,.set=&sq_kfunc_ids };
#endif

/* Provisional reservations cannot outlive a missing/failed BPF finalization.
 * This independent queue is never blocked behind a source filesystem read.
 * Scheduling is best effort, not a hard realtime reclamation guarantee. */
static void reap_provisionals(struct work_struct *work)
{
 unsigned long sq_irq_flags;
 int n;
 (void)work;
 for (n=0;n<SQ_SLOTS;n++) {
  struct file *release=NULL;
  spin_lock_irqsave(&entries_lock,sq_irq_flags);
  if(entries[n].used && entries[n].atomic_route){
   if(entries[n].atomic.state>=SQ_A_RESERVING && entries[n].atomic.state<=SQ_A_COPYING &&
      !entries[n].dropping && ktime_get_ns()>=entries[n].meta.deadline_ns)
    atomic_cancel_locked(&entries[n],-ETIMEDOUT);
   spin_unlock_irqrestore(&entries_lock,sq_irq_flags);continue;
  }
  if (entries[n].used && entries[n].meta.state==SQ_PROVISIONAL &&
      !entries[n].cancel && ktime_get_ns()>=entries[n].meta.deadline_ns) {
   release=entries[n].source;entries[n].source=NULL;entries[n].used=false;entries[n].module_held=false;
  }
  spin_unlock_irqrestore(&entries_lock,sq_irq_flags);
  if (release) { allow_write_access(release);fput(release);module_put(THIS_MODULE); }
 }
 if (!READ_ONCE(stopping)) schedule_delayed_work(&provisional_reaper,msecs_to_jiffies(100));
}

/* Called with control_lock held and cancellation already claimed under
 * entries_lock. Finalize/reaper cannot free or reuse a claimed slot. */
static void discard_entry(struct sq_entry *entry)
{
 unsigned long flags;struct file *source;void *blob;bool put,exclusion,atomic;
 spin_lock_irqsave(&entries_lock,flags);atomic=entry->atomic_route;
 spin_unlock_irqrestore(&entries_lock,flags);
 if(atomic)wait_for_completion(&entry->reservation_done);
 cancel_delayed_work_sync(&entry->work);
 if(atomic)flush_work(&entry->cleanup_work);
 spin_lock_irqsave(&entries_lock,flags);
 source=entry->source;entry->source=NULL;blob=entry->blob;entry->blob=NULL;
 exclusion=entry->meta.write_lease!=0;put=entry->module_held;entry->module_held=false;
 spin_unlock_irqrestore(&entries_lock,flags);
 if(source){if(exclusion)allow_write_access(source);fput(source);}
 kvfree(blob);if(put)module_put(THIS_MODULE);
 spin_lock_irqsave(&entries_lock,flags);
 entry->used=false;entry->atomic_route=false;entry->copy_task=NULL;
 spin_unlock_irqrestore(&entries_lock,flags);
}

static int control_open(struct inode *inode,struct file *file)
{
 unsigned long sq_irq_flags;
 struct sq_control *c;
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 c=kzalloc(sizeof(*c),GFP_KERNEL);if (!c) return -ENOMEM;
 mutex_lock(&control_lock);
 spin_lock_irqsave(&entries_lock,sq_irq_flags);
 if (controller) { spin_unlock_irqrestore(&entries_lock,sq_irq_flags);mutex_unlock(&control_lock);kfree(c);return -EBUSY; }
 controller=true;active_provider_epoch=0;file->private_data=c;
 spin_unlock_irqrestore(&entries_lock,sq_irq_flags);
 mutex_unlock(&control_lock);
 return nonseekable_open(inode,file);
}

static int control_release(struct inode *inode,struct file *file)
{
 unsigned long sq_irq_flags;
 int n;
 mutex_lock(&control_lock);
 spin_lock_irqsave(&entries_lock,sq_irq_flags);controller=false;active_provider_epoch=0;spin_unlock_irqrestore(&entries_lock,sq_irq_flags);
 for (n=0;n<SQ_SLOTS;n++) {
  bool claimed;
  spin_lock_irqsave(&entries_lock,sq_irq_flags);
  claimed=entries[n].used;
  if (claimed) {WRITE_ONCE(entries[n].cancel,true);entries[n].dropping=true;}
  spin_unlock_irqrestore(&entries_lock,sq_irq_flags);
  if (claimed) discard_entry(&entries[n]);
 }
 kfree(file->private_data);
 mutex_unlock(&control_lock);
 return 0;
}

#include "sq_atomic_control.h"

static long control_ioctl(struct file *file,unsigned int command,unsigned long arg)
{
 unsigned long sq_irq_flags;
 struct sq_control *control=file->private_data;
 struct sq_entry *entry;
 struct sq_meta meta;
 u64 id;
 long result=0;
 if (command!=SQ_STATUS && command!=SQ_SELECT && command!=SQ_DROP) return atomic_control_ioctl(file,command,arg);
 if (copy_from_user(&id,(void __user *)arg,sizeof(id))) return -EFAULT;
 mutex_lock(&control_lock);
 spin_lock_irqsave(&entries_lock,sq_irq_flags);
 entry=find_entry(id);
 if (!entry) { result=-ENOENT;spin_unlock_irqrestore(&entries_lock,sq_irq_flags);goto done; }
 if(entry->atomic_route && command!=SQ_STATUS){result=-EOPNOTSUPP;spin_unlock_irqrestore(&entries_lock,sq_irq_flags);goto done;}
 if (command==SQ_STATUS) {
  /* Read the real legacy metadata; never fabricate flags from atomic status. */
  if(entry->atomic_route && entry->atomic.state>=SQ_A_RESERVING &&
     entry->atomic.state<=SQ_A_COPYING && ktime_get_ns()>=entry->meta.deadline_ns)
   atomic_cancel_locked(entry,-ETIMEDOUT);
  if (entry->meta.state==SQ_COPYING && ktime_get_ns()>=entry->meta.deadline_ns) {
   entry->meta.state=SQ_EXPIRED_DRAINING;entry->meta.error=-ETIMEDOUT;
  }
  meta=entry->meta;
  spin_unlock_irqrestore(&entries_lock,sq_irq_flags);
  if (copy_to_user((void __user *)arg,&meta,sizeof(meta))) result=-EFAULT;
 } else if (command==SQ_SELECT) {
  if (entry->meta.state!=SQ_COMPLETE) result=-EAGAIN;
  else { control->selected=id;file->f_pos=0; }
  spin_unlock_irqrestore(&entries_lock,sq_irq_flags);
 } else {
  /* Claim while lookup is still locked. Otherwise a failed finalize could
   * free and reuse this slot before discard_entry receives the pointer. */
  WRITE_ONCE(entry->cancel,true);
  spin_unlock_irqrestore(&entries_lock,sq_irq_flags);
#ifdef SQ_LEASE_QUALIFICATION
  if (READ_ONCE(test_drop_delay_ms)) msleep(READ_ONCE(test_drop_delay_ms));
#endif
  discard_entry(entry);
  if (control->selected==id) control->selected=0;
 }
done:
 mutex_unlock(&control_lock);
 return result;
}

static ssize_t control_read(struct file *file,char __user *buf,size_t count,loff_t *position)
{
 unsigned long sq_irq_flags;
 struct sq_control *control=file->private_data;
 struct sq_entry *entry;
 ssize_t result;
 mutex_lock(&control_lock);
 spin_lock_irqsave(&entries_lock,sq_irq_flags);
 entry=find_entry(control->selected);
 if (!entry || entry->meta.state!=SQ_COMPLETE || entry->cancel) {
  spin_unlock_irqrestore(&entries_lock,sq_irq_flags);result=-ENODATA;goto done;
 }
 spin_unlock_irqrestore(&entries_lock,sq_irq_flags);
 /* Completed bytes are immutable; control_lock prevents concurrent disposal. */
 result=simple_read_from_buffer(buf,min_t(size_t,count,65536),position,entry->blob,entry->meta.size);
done:
 mutex_unlock(&control_lock);
 return result;
}
static const struct file_operations control_ops={ .owner=THIS_MODULE,.open=control_open,.release=control_release,.unlocked_ioctl=control_ioctl,.read=control_read };
static struct miscdevice device={ .minor=MISC_DYNAMIC_MINOR,.name="sq_actor_lease",.fops=&control_ops,.mode=0600 };
static int __init sq_init(void)
{
 int n,error;
 queue=alloc_ordered_workqueue("sq_actor_lease",WQ_MEM_RECLAIM);
 if (!queue) return -ENOMEM;
 BUILD_BUG_ON(sizeof(struct sq_atomic_key)!=112);
 BUILD_BUG_ON(sizeof(struct sq_atomic_request)!=136);
 BUILD_BUG_ON(sizeof(struct sq_atomic_status)!=192);
 BUILD_BUG_ON(offsetof(struct sq_atomic_status,state)!=136);
 BUILD_BUG_ON(offsetof(struct sq_atomic_status,started_ns)!=144);
 for(n=0;n<SQ_SLOTS;n++){
  INIT_DELAYED_WORK(&entries[n].work,copy_actor);
  INIT_WORK(&entries[n].cleanup_work,atomic_cleanup_actor);
  init_completion(&entries[n].reservation_done);
 }
 error=register_btf_kfunc_id_set(BPF_PROG_TYPE_LSM,&sq_kfunc_set);
 if(error)pr_err("sequester: kfunc registration failed: %d\n",error);
 if (!error) {
  error=misc_register(&device);
  if(error)pr_err("sequester: actor controller registration failed: %d\n",error);
 }
 if (error) destroy_workqueue(queue);
 else { INIT_DELAYED_WORK(&provisional_reaper,reap_provisionals);schedule_delayed_work(&provisional_reaper,msecs_to_jiffies(100)); }
 return error;
}
static void __exit sq_exit(void)
{
 int n;
 WRITE_ONCE(stopping,true);
 cancel_delayed_work_sync(&provisional_reaper);
 /* A reaped orphan can release its slot reference immediately before its
  * callback returns. Wait for every callback before module text is freed. */
 for(n=0;n<SQ_SLOTS;n++)flush_work(&entries[n].cleanup_work);
 misc_deregister(&device);
 destroy_workqueue(queue);
}
module_init(sq_init);module_exit(sq_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Sequestor isolated actor file lease qualification prototype");
