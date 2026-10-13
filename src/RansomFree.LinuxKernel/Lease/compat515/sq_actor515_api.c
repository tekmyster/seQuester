// SPDX-License-Identifier: GPL-2.0-only
/* Exact-header API qualification only. init deliberately refuses activation.
 * No probe is registered, no device created, no event emitted. The eventual
 * provider still needs provenance, loss, durable START and drain qualification.
 */
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/rcupdate.h>
#include <linux/ktime.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,15,0) || LINUX_VERSION_CODE >= KERNEL_VERSION(5,16,0)
#error Exact qualified Linux 5.15 headers required
#endif
struct sq515_frame {
    struct file *actor; /* retained F1, never exposed to userspace */
    u64 process_start_ns,task_start_ns,observed_ns;
    u32 tgid,tid,self_exec_id,uid,euid,fsuid,gid,egid,fsgid;
    long operation_result;
    /* File reference lifetime alone does not prove executable provenance. */
    bool executable_provenance_verified;
};
static struct file *sq515_current_image_reference(void)
{
    struct mm_struct *mm;
    struct file *image;
    if (READ_ONCE(current->flags)&PF_KTHREAD) return NULL;
    mm=READ_ONCE(current->mm);
    if (!mm) return NULL; /* never use a borrowed active_mm */
    rcu_read_lock();
    image=rcu_dereference(mm->exe_file);
    if (image&&!get_file_rcu(image)) image=NULL;
    rcu_read_unlock();
    return image;
}
static int sq515_entry(struct kretprobe_instance *instance,struct pt_regs *regs)
{
    struct sq515_frame *frame=(void *)instance->data;
    const struct cred *cred=current_cred();
    (void)regs;
    frame->actor=sq515_current_image_reference();
    if (!frame->actor) return 1;
    frame->tgid=task_tgid_nr(current);frame->tid=task_pid_nr(current);
    frame->process_start_ns=READ_ONCE(current->group_leader->start_boottime);
    frame->task_start_ns=READ_ONCE(current->start_boottime);
    frame->self_exec_id=READ_ONCE(current->self_exec_id);
    frame->uid=__kuid_val(cred->uid);frame->euid=__kuid_val(cred->euid);frame->fsuid=__kuid_val(cred->fsuid);
    frame->gid=__kgid_val(cred->gid);frame->egid=__kgid_val(cred->egid);frame->fsgid=__kgid_val(cred->fsgid);
    frame->observed_ns=ktime_get_ns();
    frame->executable_provenance_verified=false; /* UNAVAILABLE_PROVENANCE_515 */
    return 0;
}
static int sq515_return(struct kretprobe_instance *instance,struct pt_regs *regs)
{
    struct sq515_frame *frame=(void *)instance->data;
    frame->operation_result=(long)regs_return_value(regs);
    if(frame->actor){fput(frame->actor);frame->actor=NULL;}
    return 0;
}
static struct kretprobe sq515_probe __used={
    .kp.symbol_name="do_filp_open",.entry_handler=sq515_entry,.handler=sq515_return,
    .data_size=sizeof(struct sq515_frame),.maxactive=32
};
static int __init sq515_init(void){return -EOPNOTSUPP;}
static void __exit sq515_exit(void){}
module_init(sq515_init);module_exit(sq515_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Sequestor Linux 5.15 API build qualification; activation disabled");
