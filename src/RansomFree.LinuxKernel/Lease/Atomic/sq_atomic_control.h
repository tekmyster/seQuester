/* SPDX-License-Identifier: GPL-2.0-only */
static long atomic_control_ioctl(struct file *file,unsigned int command,unsigned long arg)
{
 struct sq_atomic_request r;struct sq_atomic_status status;
 struct sq_control *control=file->private_data;
 struct sq_entry *e=NULL;
 unsigned long flags;long result=0;bool drop=false;
 int n;
 if(command!=SQ_ATOMIC_REGISTER && command!=SQ_ATOMIC_STATUS &&
    command!=SQ_ATOMIC_NEXT && command!=SQ_ATOMIC_START &&
    command!=SQ_ATOMIC_SELECT && command!=SQ_ATOMIC_DROP)return -ENOTTY;
 if(copy_from_user(&r,(void __user *)arg,sizeof(r)))return -EFAULT;
 if(r.abi_version!=SQ_ATOMIC_ABI_VERSION || r.struct_size!=sizeof(r))return -EINVAL;
 mutex_lock(&control_lock);spin_lock_irqsave(&entries_lock,flags);
 if(!controller){result=-ENOTCONN;goto unlock;}
 if(command==SQ_ATOMIC_REGISTER){
  if(!r.key.provider_epoch)result=-EINVAL;
  else if(active_provider_epoch && active_provider_epoch!=r.key.provider_epoch)result=-EBUSY;
  else active_provider_epoch=r.key.provider_epoch;
  goto unlock;
 }
 if(command==SQ_ATOMIC_NEXT){
  for(n=0;n<SQ_SLOTS;n++)if(entries[n].used && entries[n].atomic_route &&
     entries[n].meta.id>r.key.lease_id && (!e || entries[n].meta.id<e->meta.id))e=&entries[n];
 }else e=find_entry(r.key.lease_id);
 if(!e || !e->atomic_route){result=-ENOENT;goto unlock;}
 if(command==SQ_ATOMIC_STATUS || command==SQ_ATOMIC_NEXT){
  if(e->atomic.state>=SQ_A_RESERVING && e->atomic.state<=SQ_A_COPYING &&
     ktime_get_ns()>=e->meta.deadline_ns)atomic_cancel_locked(e,-ETIMEDOUT);
  status=e->atomic;
 }else{
  if(!sq_atomic_request_valid(&r)){result=-EINVAL;goto unlock;}
  if(!sq_atomic_key_equal(&e->atomic.authorization.key,&r.key) ||
     r.key.provider_epoch!=active_provider_epoch){result=-ESTALE;goto unlock;}
  if(e->dropping){result=-EALREADY;goto unlock;}
  if(command==SQ_ATOMIC_START){
   result=sq_atomic_accept_start(&e->atomic,&r,ktime_get_ns(),active_provider_epoch);
   if(result==0){
    /* Only the first durably authorized START changes the budget. Exact
     * retransmissions never renew either the lease or the copy deadline. */
    e->meta.deadline_ns=ktime_get_ns()+SQ_ATOMIC_BUDGET_NS;
    e->atomic.deadline_ns=e->meta.deadline_ns;
    if(!queue_delayed_work(queue,&e->work,0)){
     atomic_cancel_locked(e,-EIO);result=-EIO;
    }
   }else if(result==1)result=0; /* exact retry, never a second dispatch */
   else if(e->atomic.state==SQ_A_ABORT_DRAINING)atomic_cancel_locked(e,e->atomic.error);
  }else{
   if(r.raw_receipt_low!=e->atomic.authorization.raw_receipt_low ||
      r.raw_receipt_high!=e->atomic.authorization.raw_receipt_high){result=-ESTALE;goto unlock;}
   if(command==SQ_ATOMIC_SELECT){
    if(e->atomic.state!=SQ_A_COMPLETE || e->cancel || e->meta.state!=SQ_COMPLETE)
     result=-EAGAIN;
    else {control->selected=e->meta.id;file->f_pos=0;}
   }else{
    e->dropping=true;WRITE_ONCE(e->cancel,true);
    e->meta.state=SQ_FAILED;e->atomic.state=SQ_A_ABORT_DRAINING;drop=true;
   }
  }
 }
unlock:
 spin_unlock_irqrestore(&entries_lock,flags);
 if(!result && (command==SQ_ATOMIC_STATUS || command==SQ_ATOMIC_NEXT)){
  if(copy_to_user((void __user *)arg,&status,sizeof(status)))result=-EFAULT;
 }
 if(drop){discard_entry(e);if(control->selected==r.key.lease_id)control->selected=0;}
 mutex_unlock(&control_lock);return result;
}
