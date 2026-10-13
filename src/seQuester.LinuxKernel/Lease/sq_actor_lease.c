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
#include <linux/delay.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/magic.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include "sq_lease.h"

#define SQ_SLOTS 4
#define SQ_MAX_BYTES (4 * 1024 * 1024)
#define SQ_BUDGET_NS (2ULL * NSEC_PER_SEC)
struct sq_entry {
 struct delayed_work work;
 struct file *source;
 void *blob;
 struct sq_meta meta;
 struct timespec64 mtime, ctime;
 bool used, cancel;
};
struct sq_control { u64 selected; };
static struct sq_entry entries[SQ_SLOTS];
static DEFINE_MUTEX(entries_lock);
static DEFINE_MUTEX(control_lock);
static struct workqueue_struct *queue;
static bool controller;
static u64 next_id;
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
 struct sq_entry *entry=container_of(to_delayed_work(work),struct sq_entry,work);
 struct file *source=entry->source;
 struct inode *inode=file_inode(source);
 struct timespec64 mt,ct;
 loff_t offset=0;
 void *blob=NULL;
 int error=0;
 ssize_t got;
 u64 finished;
 mutex_lock(&entries_lock);
 entry->meta.state=SQ_COPYING;
 mutex_unlock(&entries_lock);
 if (ktime_get_ns()>=entry->meta.deadline_ns) { error=-ETIMEDOUT; goto done; }
 blob=kvmalloc(entry->meta.size,GFP_KERNEL);
 if (!blob) { error=-ENOMEM; goto done; }
 while (offset<entry->meta.size) {
  if (READ_ONCE(entry->cancel)) { error=-ECANCELED; break; }
  if (ktime_get_ns()>=entry->meta.deadline_ns) { error=-ETIMEDOUT; break; }
  got=kernel_read(source,blob+offset,min_t(u64,65536,entry->meta.size-offset),&offset);
  if (got<=0) { error=got<0?got:-EIO; break; }
  mutex_lock(&entries_lock);
  entry->meta.bytes=offset;
  mutex_unlock(&entries_lock);
 }
 mt=inode_get_mtime(inode);ct=inode_get_ctime(inode);
 /* Rename may change ctime without changing bytes. The referenced ext4
  * object and held write exclusion bind the copy across that path change. */
 mutex_lock(&entries_lock);
 entry->meta.metadata_changed=!timespec64_equal(&ct,&entry->ctime);
 mutex_unlock(&entries_lock);
 if (!error && (i_size_read(inode)!=entry->meta.size ||
     !timespec64_equal(&mt,&entry->mtime)))
  error=-ESTALE;
done:
 /* Retain the write exclusion until all kernel_read calls have returned. */
 mutex_lock(&entries_lock);
 allow_write_access(source);
 entry->source=NULL;
 entry->meta.write_lease=0;
 mutex_unlock(&entries_lock);
 fput(source);
#ifdef SQ_LEASE_QUALIFICATION
 if (READ_ONCE(test_publish_delay_ms)) msleep(READ_ONCE(test_publish_delay_ms));
#endif
 mutex_lock(&entries_lock);
 /* One timestamp defines completion. An observer-declared expiry is sticky. */
 finished=ktime_get_ns();
 if (READ_ONCE(entry->cancel)) error=-ECANCELED;
 if (entry->meta.state==SQ_EXPIRED_DRAINING || finished>=entry->meta.deadline_ns) error=-ETIMEDOUT;
 entry->meta.finished_ns=finished;
 entry->meta.error=error;
 entry->meta.state=error?SQ_FAILED:SQ_COMPLETE;
 if (!error) { entry->blob=blob;blob=NULL; }
 mutex_unlock(&entries_lock);
 kvfree(blob);
}

__bpf_kfunc_start_defs();
__bpf_kfunc s64 sq_lease_capture_file(struct file *source,u64 cookie)
{
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
 mutex_lock(&entries_lock);
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
 mutex_unlock(&entries_lock);
#ifdef SQ_LEASE_QUALIFICATION
 /* Native race fixture only: let another shared-mm task attempt reassignment
  * between the two BPF provenance snapshots. Never included by default. */
 if (result>0 && READ_ONCE(test_capture_delay_ms)) msleep(READ_ONCE(test_capture_delay_ms));
#endif
 return result;
}

__bpf_kfunc s64 sq_lease_finalize(u64 id,u64 cookie,u64 generation,s64 association_error,u64 provider_epoch)
{
 struct sq_entry *entry;
 struct file *release=NULL;
 bool queued=false,put=false;
 s64 result=0;
 mutex_lock(&entries_lock);
 entry=find_entry(id);
 if (!entry) { result=-ENOENT;goto out; }
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
 release=entry->source;entry->source=NULL;entry->used=false;put=true;
out:
 mutex_unlock(&entries_lock);
 if (release) { allow_write_access(release);fput(release); }
 if (put) module_put(THIS_MODULE);
 return result;
}
__bpf_kfunc_end_defs();

BTF_KFUNCS_START(sq_kfunc_ids)
BTF_ID_FLAGS(func,sq_lease_capture_file,KF_TRUSTED_ARGS | KF_SLEEPABLE)
BTF_ID_FLAGS(func,sq_lease_finalize,KF_SLEEPABLE)
BTF_KFUNCS_END(sq_kfunc_ids)
static const struct btf_kfunc_id_set sq_kfunc_set={ .owner=THIS_MODULE,.set=&sq_kfunc_ids };

/* Provisional reservations cannot outlive a missing/failed BPF finalization.
 * This independent queue is never blocked behind a source filesystem read.
 * Scheduling is best effort, not a hard realtime reclamation guarantee. */
static void reap_provisionals(struct work_struct *work)
{
 int n;
 (void)work;
 for (n=0;n<SQ_SLOTS;n++) {
  struct file *release=NULL;
  mutex_lock(&entries_lock);
  if (entries[n].used && entries[n].meta.state==SQ_PROVISIONAL &&
      !entries[n].cancel && ktime_get_ns()>=entries[n].meta.deadline_ns) {
   release=entries[n].source;entries[n].source=NULL;entries[n].used=false;
  }
  mutex_unlock(&entries_lock);
  if (release) { allow_write_access(release);fput(release);module_put(THIS_MODULE); }
 }
 if (!READ_ONCE(stopping)) schedule_delayed_work(&provisional_reaper,msecs_to_jiffies(100));
}

/* Called with control_lock held and cancellation already claimed under
 * entries_lock. Finalize/reaper cannot free or reuse a claimed slot. */
static void discard_entry(struct sq_entry *entry)
{
 cancel_delayed_work_sync(&entry->work);
 {
  struct file *source;
  void *blob;
  mutex_lock(&entries_lock);
  source=entry->source;entry->source=NULL;
  blob=entry->blob;entry->blob=NULL;entry->used=false;
  mutex_unlock(&entries_lock);
  if (source) { allow_write_access(source);fput(source); }
  kvfree(blob);module_put(THIS_MODULE);
 }
}

static int control_open(struct inode *inode,struct file *file)
{
 struct sq_control *c;
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 c=kzalloc(sizeof(*c),GFP_KERNEL);if (!c) return -ENOMEM;
 mutex_lock(&control_lock);
 mutex_lock(&entries_lock);
 if (controller) { mutex_unlock(&entries_lock);mutex_unlock(&control_lock);kfree(c);return -EBUSY; }
 controller=true;file->private_data=c;
 mutex_unlock(&entries_lock);
 mutex_unlock(&control_lock);
 return nonseekable_open(inode,file);
}

static int control_release(struct inode *inode,struct file *file)
{
 int n;
 mutex_lock(&control_lock);
 mutex_lock(&entries_lock);controller=false;mutex_unlock(&entries_lock);
 for (n=0;n<SQ_SLOTS;n++) {
  bool claimed;
  mutex_lock(&entries_lock);
  claimed=entries[n].used;
  if (claimed) WRITE_ONCE(entries[n].cancel,true);
  mutex_unlock(&entries_lock);
  if (claimed) discard_entry(&entries[n]);
 }
 kfree(file->private_data);
 mutex_unlock(&control_lock);
 return 0;
}

static long control_ioctl(struct file *file,unsigned int command,unsigned long arg)
{
 struct sq_control *control=file->private_data;
 struct sq_entry *entry;
 struct sq_meta meta;
 u64 id;
 long result=0;
 if (command!=SQ_STATUS && command!=SQ_SELECT && command!=SQ_DROP) return -ENOTTY;
 if (copy_from_user(&id,(void __user *)arg,sizeof(id))) return -EFAULT;
 mutex_lock(&control_lock);
 mutex_lock(&entries_lock);
 entry=find_entry(id);
 if (!entry) { result=-ENOENT;mutex_unlock(&entries_lock);goto done; }
 if (command==SQ_STATUS) {
  if (entry->meta.state==SQ_COPYING && ktime_get_ns()>=entry->meta.deadline_ns) {
   entry->meta.state=SQ_EXPIRED_DRAINING;entry->meta.error=-ETIMEDOUT;
  }
  meta=entry->meta;
  mutex_unlock(&entries_lock);
  if (copy_to_user((void __user *)arg,&meta,sizeof(meta))) result=-EFAULT;
 } else if (command==SQ_SELECT) {
  if (entry->meta.state!=SQ_COMPLETE) result=-EAGAIN;
  else { control->selected=id;file->f_pos=0; }
  mutex_unlock(&entries_lock);
 } else {
  /* Claim while lookup is still locked. Otherwise a failed finalize could
   * free and reuse this slot before discard_entry receives the pointer. */
  WRITE_ONCE(entry->cancel,true);
  mutex_unlock(&entries_lock);
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
 struct sq_control *control=file->private_data;
 struct sq_entry *entry;
 ssize_t result;
 mutex_lock(&control_lock);
 mutex_lock(&entries_lock);
 entry=find_entry(control->selected);
 if (!entry || entry->meta.state!=SQ_COMPLETE) {
  mutex_unlock(&entries_lock);result=-ENODATA;goto done;
 }
 mutex_unlock(&entries_lock);
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
 for (n=0;n<SQ_SLOTS;n++) INIT_DELAYED_WORK(&entries[n].work,copy_actor);
 error=register_btf_kfunc_id_set(BPF_PROG_TYPE_LSM,&sq_kfunc_set);
 if (!error) error=misc_register(&device);
 if (error) destroy_workqueue(queue);
 else { INIT_DELAYED_WORK(&provisional_reaper,reap_provisionals);schedule_delayed_work(&provisional_reaper,msecs_to_jiffies(100)); }
 return error;
}
static void __exit sq_exit(void)
{
 WRITE_ONCE(stopping,true);
 cancel_delayed_work_sync(&provisional_reaper);
 misc_deregister(&device);
 destroy_workqueue(queue);
}
module_init(sq_init);module_exit(sq_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Sequestor isolated actor file lease qualification prototype");
