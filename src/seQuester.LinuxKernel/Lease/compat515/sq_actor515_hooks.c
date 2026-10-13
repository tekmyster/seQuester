// SPDX-License-Identifier: GPL-2.0-only
/* Lifecycle integration candidate. init refuses activation until the complete
 * direct-operation, unresolved-target lease and durable-receipt gates exist.
 * These are real typed Linux 5.15 APIs, not a deployed capture provider.
 */
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/tracepoint.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/mm_types.h>
#include <linux/binfmts.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include "sq515_provenance.h"
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,15,0) || LINUX_VERSION_CODE >= KERNEL_VERSION(5,16,0)
#error Exact qualified Linux 5.15 headers required
#endif
static struct sq515_provenance_table provenance;
static DEFINE_SPINLOCK(provenance_lock);
static bool stopping=true;
static struct tracepoint *exec_point,*fork_point,*exit_point;
static bool exec_registered,fork_registered,exit_registered,replace_registered;
static unsigned long last_replace_missed;
static struct kprobe replace_probe;

static struct sq515_task_identity task_identity(struct task_struct *task)
{
 struct sq515_task_identity result;
 result.tgid=task_tgid_nr(task);result.tid=task_pid_nr(task);
 result.process_start_ns=READ_ONCE(task->group_leader->start_boottime);
 result.task_start_ns=READ_ONCE(task->start_boottime);
 result.self_exec_id=READ_ONCE(task->self_exec_id);
 return result;
}
/* lock held; counters contain health loss, never a manufactured operation. */
static void sample_replace_loss(void)
{
 unsigned long observed=READ_ONCE(replace_probe.nmissed);
 if(observed==last_replace_missed)return;
 if(observed<last_replace_missed)provenance.disabled=true;
 sq515_provenance_loss(&provenance);last_replace_missed=observed;
}
static void observed_exec(void *unused,struct task_struct *task,pid_t old_pid,
                          struct linux_binprm *binprm)
{
 unsigned long flags;
 struct sq515_task_identity identity;
 struct mm_struct *mm;
 bool singleton;
 (void)unused;(void)old_pid;(void)binprm;
 if(READ_ONCE(stopping))return;
 // Only live callback arguments are read. No task/mm/binprm pointer survives.
 spin_lock_irqsave(&provenance_lock,flags);
 if(stopping)goto done;
 sample_replace_loss();
 if(task!=current){sq515_provenance_loss(&provenance);goto done;}
 identity=task_identity(task);mm=READ_ONCE(task->mm);
 singleton=mm && !(READ_ONCE(task->flags)&PF_KTHREAD) &&
   thread_group_leader(task) && atomic_read(&mm->mm_users)==1;
 sq515_provenance_commit_exec(&provenance,&identity,singleton);
 sample_replace_loss();
done:spin_unlock_irqrestore(&provenance_lock,flags);
}
static void observed_fork(void *unused,struct task_struct *parent,
                          struct task_struct *child)
{
 unsigned long flags;
 struct sq515_task_identity identity;
 struct mm_struct *parent_mm;
 (void)unused;
 if(READ_ONCE(stopping))return;
 spin_lock_irqsave(&provenance_lock,flags);
 if(stopping)goto done;
 sample_replace_loss();parent_mm=READ_ONCE(parent->mm);
 if(parent_mm && parent_mm==READ_ONCE(child->mm)){
  identity=task_identity(parent);
  sq515_provenance_taint(&provenance,&identity,SQ515_SHARED_MM_TAINTED);
 }
 // No child inherits a clean row, including fork without CLONE_VM.
done:spin_unlock_irqrestore(&provenance_lock,flags);
}
static void observed_exit(void *unused,struct task_struct *task)
{
 unsigned long flags;
 struct sq515_task_identity identity;
 (void)unused;
 if(READ_ONCE(stopping))return;
 identity=task_identity(task);
 spin_lock_irqsave(&provenance_lock,flags);
 if(!stopping)sq515_provenance_exit(&provenance,&identity);
 spin_unlock_irqrestore(&provenance_lock,flags);
}
static int replacement_attempt(struct kprobe *probe,struct pt_regs *regs)
{
 unsigned long flags;
 struct sq515_task_identity identity;
 (void)probe;(void)regs;
 if(READ_ONCE(stopping))return 0;
 identity=task_identity(current);
 spin_lock_irqsave(&provenance_lock,flags);
 if(!stopping){sample_replace_loss();sq515_provenance_taint(&provenance,&identity,SQ515_PR_SET_MM_TAINTED);}
 spin_unlock_irqrestore(&provenance_lock,flags);
 return 0;
}
static void locate_tracepoint(struct tracepoint *point,void *unused)
{
 (void)unused;
 if(!strcmp(point->name,"sched_process_exec"))exec_point=point;
 else if(!strcmp(point->name,"sched_process_fork"))fork_point=point;
 else if(!strcmp(point->name,"sched_process_exit"))exit_point=point;
}
static void lifecycle_unregister(void)
{
 unsigned long flags;
 spin_lock_irqsave(&provenance_lock,flags);stopping=true;
 spin_unlock_irqrestore(&provenance_lock,flags);
 if(replace_registered){unregister_kprobe(&replace_probe);replace_registered=false;}
 if(exit_registered){tracepoint_probe_unregister(exit_point,observed_exit,NULL);exit_registered=false;}
 if(fork_registered){tracepoint_probe_unregister(fork_point,observed_fork,NULL);fork_registered=false;}
 if(exec_registered){tracepoint_probe_unregister(exec_point,observed_exec,NULL);exec_registered=false;}
 tracepoint_synchronize_unregister();
}
static int __used lifecycle_register(void)
{
 int error;
 // This startup method must later be called only by the exact admitted source
 // controller. Existing tasks retain unknown provenance throughout startup.
 for_each_kernel_tracepoint(locate_tracepoint,NULL);
 if(!exec_point || !fork_point || !exit_point)return -EOPNOTSUPP;
 error=tracepoint_probe_register(exec_point,observed_exec,NULL);if(error)goto failed;exec_registered=true;
 error=tracepoint_probe_register(fork_point,observed_fork,NULL);if(error)goto failed;fork_registered=true;
 error=tracepoint_probe_register(exit_point,observed_exit,NULL);if(error)goto failed;exit_registered=true;
 replace_probe.symbol_name="replace_mm_exe_file";replace_probe.pre_handler=replacement_attempt;
 error=register_kprobe(&replace_probe);if(error)goto failed;replace_registered=true;
 // No operation admission is enabled by this compile-only candidate.
 return 0;
failed:lifecycle_unregister();return error;
}
static struct sq515_provenance_snapshot __used observe_current(void)
{
 unsigned long flags;
 struct sq515_task_identity identity=task_identity(current);
 struct sq515_provenance_snapshot result={0,0,SQ515_STARTUP_UNKNOWN,false};
 spin_lock_irqsave(&provenance_lock,flags);
 if(stopping)goto done;
 sample_replace_loss();result=sq515_provenance_observe(&provenance,&identity);
 sample_replace_loss();
 if(result.loss_epoch!=provenance.loss_epoch){result.clean=false;result.state=SQ515_LOSS_UNKNOWN;result.generation=0;}
done:spin_unlock_irqrestore(&provenance_lock,flags);return result;
}
static int __init hooks_init(void)
{
 sq515_provenance_init(&provenance);
 return -EOPNOTSUPP; // no module parameter can override this pending gate
}
static void __exit hooks_exit(void){lifecycle_unregister();}
module_init(hooks_init);module_exit(hooks_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Sequestor Linux 5.15 lifecycle API qualification; activation disabled");
