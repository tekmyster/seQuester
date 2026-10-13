/* SPDX-License-Identifier: GPL-2.0-only
 * Native candidate. Included inside this module's kfunc definition block.
 * Entry ownership is shared with the legacy four slots, never a second pool.
 */
static void discard_entry(struct sq_entry *entry);
static bool atomic_task_matches(struct sq_entry *e,u64 cookie,bool check_exec)
{
 struct sq_atomic_key *k=&e->atomic.authorization.key;
 return e->atomic_route && k->cookie==cookie &&
  k->tgid==task_tgid_nr(current) && k->tid==task_pid_nr(current) &&
  k->process_start_ns==current->group_leader->start_boottime &&
  k->task_start_ns==current->start_boottime &&
  (!check_exec || k->self_exec_id==READ_ONCE(current->self_exec_id));
}
/* entries_lock held. Dispatch is committed before STOP can inspect the slot. */
static void atomic_cancel_locked(struct sq_entry *e,int error)
{
 if (e->atomic.state==SQ_A_COMPLETE || e->atomic.state==SQ_A_UNAVAILABLE)
  return;
 WRITE_ONCE(e->cancel,true);
 if (!e->atomic.error) e->atomic.error=error;
 e->atomic.state=SQ_A_ABORT_DRAINING;
 if (error==-ETIMEDOUT) e->meta.state=SQ_EXPIRED_DRAINING;
 if(!e->cleanup_queued){
  e->cleanup_queued=true;
  queue_work(system_unbound_wq,&e->cleanup_work);
 }
}

static s64 atomic_reserve(struct file *actor,u64 cookie,u64 nonce,u64 target_inode,u64 target_device)
{
 unsigned long flags;
 struct sq_entry *e=NULL;
 struct inode *inode=file_inode(actor);
 struct sq_atomic_key *k;
 struct file *owned=NULL;
 struct timespec64 mt={0},ct={0};
 loff_t size=0;
 u64 id;
 int n,error=0;
 bool excluded=false;
 if (!cookie || !nonce || !target_inode || target_device>0xffffffffULL || !READ_ONCE(current->self_exec_id)) return -EINVAL;
 if (!try_module_get(THIS_MODULE)) return -ENODEV;
 spin_lock_irqsave(&entries_lock,flags);
 if (!controller || !active_provider_epoch) { error=-ENOTCONN;goto unclaimed; }
 if (next_id==S64_MAX) { error=-EOVERFLOW;goto unclaimed; }
 for(n=0;n<SQ_SLOTS;n++) if(!entries[n].used){e=&entries[n];break;}
 if(!e){error=-ENOSPC;goto unclaimed;}
 reinit_completion(&e->reservation_done);
 memset(&e->meta,0,sizeof(e->meta));memset(&e->atomic,0,sizeof(e->atomic));
 e->used=true;e->atomic_route=true;e->module_held=true;
 e->dropping=false;e->cancel=false;e->cleanup_queued=false;e->blob=NULL;e->source=NULL;
 e->copy_task=NULL;
 e->meta.id=++next_id;e->meta.cookie=cookie;
 e->meta.started_ns=ktime_get_ns();e->meta.deadline_ns=e->meta.started_ns+SQ_ATOMIC_RETENTION_NS;
 e->meta.schema_version=2;e->meta.struct_size=sizeof(e->meta);
 e->meta.state=SQ_PENDING;
 e->atomic.authorization.abi_version=SQ_ATOMIC_ABI_VERSION;
 e->atomic.authorization.struct_size=sizeof(struct sq_atomic_request);
 e->atomic.state=SQ_A_RESERVING;
 k=&e->atomic.authorization.key;
 k->lease_id=e->meta.id;k->cookie=cookie;k->operation_nonce=nonce;
 k->tgid=task_tgid_nr(current);k->tid=task_pid_nr(current);
 k->task_start_ns=current->start_boottime;
 k->process_start_ns=current->group_leader->start_boottime;
 k->self_exec_id=READ_ONCE(current->self_exec_id);
 k->provider_epoch=active_provider_epoch;
 /* Checked hook observations, NOT a native held-target reference. */
 k->target_device=target_device;k->target_inode=target_inode;
 e->atomic.started_ns=e->meta.started_ns;e->atomic.deadline_ns=e->meta.deadline_ns;
 id=e->meta.id;
 spin_unlock_irqrestore(&entries_lock,flags);

 /* F1 remains verifier-owned and live until this function returns. No stored
  * target pointer, allocation, path rendering, read, wait or fput here. */
 if(!S_ISREG(inode->i_mode) || inode->i_sb->s_magic!=EXT4_SUPER_MAGIC)
  error=-EOPNOTSUPP;
 else if((actor->f_mode&(FMODE_READ|FMODE_CAN_READ))!=(FMODE_READ|FMODE_CAN_READ))
  error=-EBADF;
 else {
  get_file(actor);owned=actor;
  error=deny_write_access(owned);excluded=!error;
  if(!error){
   size=i_size_read(inode);
   if(size<=0 || size>SQ_MAX_BYTES)error=-EFBIG;
   mt=inode_get_mtime(inode);ct=inode_get_ctime(inode);
  }
 }
 spin_lock_irqsave(&entries_lock,flags);
 e->source=owned;e->meta.write_lease=excluded;
 e->meta.size=size;e->meta.inode=inode->i_ino;e->meta.device=inode->i_sb->s_dev;
 e->mtime=mt;e->ctime=ct;
 k=&e->atomic.authorization.key;
 k->actor_device=e->meta.device;k->actor_inode=e->meta.inode;
 e->meta.tgid=k->tgid;e->meta.tid=k->tid;
 e->meta.process_start_ns=k->process_start_ns;e->meta.task_start_ns=k->task_start_ns;
 e->meta.self_exec_id=k->self_exec_id;e->meta.provider_epoch=k->provider_epoch;
 e->atomic.size=size;e->atomic.f2_owned=owned!=NULL;
 e->atomic.write_exclusion_owned=excluded;
 if(!error && (!controller || active_provider_epoch!=k->provider_epoch || e->cancel))error=-ECANCELED;
 if(!error && ktime_get_ns()>=e->meta.deadline_ns)error=-ETIMEDOUT;
 if(error)atomic_cancel_locked(e,error);
 else e->atomic.state=SQ_A_RESERVED_RAW_PENDING;
 /* Cleanup/close cannot claim completed handoff until all owned fields and
  * cleanup dispatch are published. A RESERVING slot always remains used. */
 complete_all(&e->reservation_done);
 spin_unlock_irqrestore(&entries_lock,flags);
 return error?error:(s64)id;
unclaimed:
 spin_unlock_irqrestore(&entries_lock,flags);
 module_put(THIS_MODULE);
 return error;
}

/* Only actor is a pointer: verifier-owned F1 -> independently owned F2.
 * Target scalars are checked BPF observations from the admitted hook/watch
 * source. They require source/raw/map/provenance validation in managed mode.
 * This API neither holds a target nor establishes a completed I/O result. */
__bpf_kfunc s64 sq_lease_reserve_observed_atomic(struct file *actor,u64 cookie,u64 nonce,u64 target_inode,u64 target_device)
{ return atomic_reserve(actor,cookie,nonce,target_inode,target_device); }
/* Compatibility verifier probe has no target identity and cannot copy. */
__bpf_kfunc s64 sq_lease_capture_file_atomic(struct file *source,u64 cookie)
{ (void)source;(void)cookie;return -EOPNOTSUPP; }
__bpf_kfunc s64 sq_lease_finalize_atomic(u64 id,u64 cookie,u64 generation,s64 issue,u64 epoch)
{
 unsigned long flags;struct sq_entry *e;s64 result=0;
 spin_lock_irqsave(&entries_lock,flags);e=find_entry(id);
 if(!e || !e->atomic_route){result=-ENOENT;goto out;}
 if(!atomic_task_matches(e,cookie,true)){result=-ESTALE;goto out;}
 if(e->atomic.state!=SQ_A_RESERVED_RAW_PENDING || e->cancel){result=-EALREADY;goto out;}
 if(!controller || epoch!=active_provider_epoch || epoch!=e->atomic.authorization.key.provider_epoch)
  issue=-ESTALE;
 if(!issue && (!generation || (generation&1)))issue=-EINVAL;
 if(issue>0 || issue < -4095)issue=-EINVAL;
 if(ktime_get_ns()>=e->meta.deadline_ns)issue=-ETIMEDOUT;
 e->meta.association_generation=generation;e->meta.association_error=issue;
 e->meta.association_state=issue?2:1;
 e->atomic.authorization.key.association_generation=generation;
 if(issue){atomic_cancel_locked(e,issue);result=issue;}
 else e->atomic.state=SQ_A_FINALIZED_RAW_PENDING;
out:spin_unlock_irqrestore(&entries_lock,flags);return result;
}
__bpf_kfunc s64 sq_lease_abort_atomic(u64 id,u64 cookie,s64 issue)
{
 unsigned long flags;struct sq_entry *e;s64 result=0;
 if(issue>=0 || issue < -4095)issue=-ECANCELED;
 spin_lock_irqsave(&entries_lock,flags);e=find_entry(id);
 if(!e || !e->atomic_route)result=-ENOENT;
 else if(!atomic_task_matches(e,cookie,false))result=-ESTALE;
 else if(e->atomic.state==SQ_A_COMPLETE || e->atomic.state==SQ_A_UNAVAILABLE)result=-EALREADY;
 else atomic_cancel_locked(e,issue);
 spin_unlock_irqrestore(&entries_lock,flags);return result;
}
/* Exact native copy-worker identity, not a pathname/user suppression rule. */
__bpf_kfunc int sq_actor_copy_active(void)
{
 unsigned long flags;int n,result=0;
 spin_lock_irqsave(&entries_lock,flags);
 for(n=0;n<SQ_SLOTS;n++)if(entries[n].used && entries[n].copy_task==current){result=1;break;}
 spin_unlock_irqrestore(&entries_lock,flags);return result;
}

static void atomic_cleanup_actor(struct work_struct *work)
{
 struct sq_entry *e=container_of(work,struct sq_entry,cleanup_work);
 struct file *source;void *blob;
 unsigned long flags;bool exclusion,erase=false,put=false;
 wait_for_completion(&e->reservation_done);
 cancel_delayed_work_sync(&e->work);
 spin_lock_irqsave(&entries_lock,flags);
 source=e->source;e->source=NULL;blob=e->blob;e->blob=NULL;
 exclusion=e->meta.write_lease!=0;
 spin_unlock_irqrestore(&entries_lock,flags);
 if(source){if(exclusion)allow_write_access(source);fput(source);}
 kvfree(blob);
 spin_lock_irqsave(&entries_lock,flags);
 e->meta.write_lease=0;e->meta.finished_ns=ktime_get_ns();
 e->meta.state=SQ_FAILED;e->meta.error=e->atomic.error?e->atomic.error:-ECANCELED;
 e->atomic.error=e->meta.error;e->atomic.finished_ns=e->meta.finished_ns;
 e->atomic.f2_owned=0;e->atomic.write_exclusion_owned=0;
 e->atomic.state=SQ_A_UNAVAILABLE;e->copy_task=NULL;
 /* No-START and ring-loss orphans are natively reclaimed after real drain.
  * Receipt-bearing slots remain resident for exact diagnostic/DROP evidence. */
 erase=!e->dropping && !e->atomic.authorization.raw_receipt_low &&
       !e->atomic.authorization.raw_receipt_high;
 if(erase){e->dropping=true;put=e->module_held;e->module_held=false;}
 spin_unlock_irqrestore(&entries_lock,flags);
 if(put)module_put(THIS_MODULE);
 if(erase){
  spin_lock_irqsave(&entries_lock,flags);e->used=false;e->atomic_route=false;
  spin_unlock_irqrestore(&entries_lock,flags);
 }
}
