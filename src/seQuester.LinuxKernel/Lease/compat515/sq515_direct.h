/* SPDX-License-Identifier: GPL-2.0-only
 * Scalar correlation for direct do_sys_openat2 -> do_filp_open observations.
 * Caller holds its IRQ-safe lock. No task, filename, file or probe-instance
 * pointer is retained here. This component cannot grant a copy or whitelist.
 */
#ifndef SQ515_DIRECT_H
#define SQ515_DIRECT_H
#include "sq515_provenance.h"
#define SQ515_DIRECT_SLOTS 32
enum sq515_direct_class {
 SQ515_DIRECT_UNKNOWN=0,
 SQ515_DIRECT_FILP_OBSERVED=1,
 SQ515_DIRECT_BEFORE_FILP_FAILURE=2,
 SQ515_DIRECT_INCOMPLETE=3
};
struct sq515_direct_key {
 struct sq515_task_identity task;
 __u64 source_epoch,nonce,loss_epoch;
};
struct sq515_direct_entry {
 struct sq515_direct_key key;
 __s64 filp_status;
 bool used,filp_entered,filp_returned,ambiguous;
};
struct sq515_direct_table {
 struct sq515_direct_entry entries[SQ515_DIRECT_SLOTS];
 __u64 source_epoch,next_nonce,loss_epoch;
 bool disabled;
};
struct sq515_direct_result {
 struct sq515_direct_key key;
 __s64 syscall_status,filp_status;
 __u32 observation_class;
 bool complete;
};
static inline bool sq515_direct_key_equal(const struct sq515_direct_key *a,
                                          const struct sq515_direct_key *b)
{
 return a->source_epoch==b->source_epoch && a->nonce==b->nonce &&
  a->loss_epoch==b->loss_epoch && sq515_same_identity(&a->task,&b->task);
}
static inline void sq515_direct_init(struct sq515_direct_table *table,
                                     __u64 source_epoch)
{
 memset(table,0,sizeof(*table));table->source_epoch=source_epoch;
 table->loss_epoch=1;table->disabled=source_epoch==0;
}
static inline void sq515_direct_loss(struct sq515_direct_table *table)
{
 unsigned int i;
 if(table->loss_epoch==~(__u64)0)table->disabled=true;
 else table->loss_epoch++;
 // Keep live rows occupied until their exact return/exit. Never reuse a slot
 // while its outer callback still exists.
 for(i=0;i<SQ515_DIRECT_SLOTS;i++)
  if(table->entries[i].used)table->entries[i].ambiguous=true;
}
static inline int sq515_direct_find(struct sq515_direct_table *table,
                                    const struct sq515_task_identity *task)
{
 unsigned int i;
 for(i=0;i<SQ515_DIRECT_SLOTS;i++)
  if(table->entries[i].used && sq515_same_lifetime(&table->entries[i].key.task,task))
   return (int)i;
 return -1;
}
static inline bool sq515_direct_begin(struct sq515_direct_table *table,
                                      const struct sq515_task_identity *task,
                                      struct sq515_direct_key *key)
{
 unsigned int i;int existing;
 memset(key,0,sizeof(*key));
 if(table->disabled || !sq515_identity_valid(task))return false;
 existing=sq515_direct_find(table,task);
 if(existing>=0){table->entries[existing].ambiguous=true;return false;}
 if(table->next_nonce==~(__u64)0){table->disabled=true;return false;}
 for(i=0;i<SQ515_DIRECT_SLOTS;i++)if(!table->entries[i].used){
  struct sq515_direct_entry *row=&table->entries[i];
  memset(row,0,sizeof(*row));row->used=true;
  row->key.task=*task;row->key.source_epoch=table->source_epoch;
  row->key.nonce=++table->next_nonce;row->key.loss_epoch=table->loss_epoch;
  *key=row->key;return true;
 }
 sq515_direct_loss(table);return false;
}
static inline bool sq515_direct_filp_enter(struct sq515_direct_table *table,
                                           const struct sq515_task_identity *task,
                                           struct sq515_direct_key *key)
{
 int slot=sq515_direct_find(table,task);
 struct sq515_direct_entry *row;
 memset(key,0,sizeof(*key));
 if(slot<0 || table->disabled)return false;
 row=&table->entries[slot];
 if(!sq515_same_identity(&row->key.task,task) || row->ambiguous ||
    row->key.loss_epoch!=table->loss_epoch || row->filp_entered){
  row->ambiguous=true;return false;
 }
 row->filp_entered=true;*key=row->key;return true;
}
static inline bool sq515_direct_filp_return(struct sq515_direct_table *table,
                                            const struct sq515_direct_key *key,
                                            __s64 status)
{
 int slot=sq515_direct_find(table,&key->task);
 struct sq515_direct_entry *row;
 if(slot<0 || table->disabled)return false;
 row=&table->entries[slot];
 if(!sq515_direct_key_equal(&row->key,key) || row->ambiguous ||
    row->key.loss_epoch!=table->loss_epoch || !row->filp_entered ||
    row->filp_returned || status>0 || status < -4095){
  // Never serialize a successful struct file pointer: only zero or -errno.
  if(sq515_direct_key_equal(&row->key,key))row->ambiguous=true;
  return false;
 }
 row->filp_status=status;row->filp_returned=true;return true;
}
static inline struct sq515_direct_result sq515_direct_finish(
 struct sq515_direct_table *table,const struct sq515_direct_key *key,
 __s64 syscall_status)
{
 int slot=sq515_direct_find(table,&key->task);
 struct sq515_direct_result result;
 struct sq515_direct_entry *row;
 memset(&result,0,sizeof(result));result.key=*key;
 result.syscall_status=syscall_status;result.observation_class=SQ515_DIRECT_UNKNOWN;
 if(slot<0)return result;
 row=&table->entries[slot];
 // A stale return cannot clear a new lifetime or a different operation.
 if(!sq515_direct_key_equal(&row->key,key))return result;
 result.observation_class=SQ515_DIRECT_INCOMPLETE;
 if(!table->disabled && !row->ambiguous &&
    row->key.loss_epoch==table->loss_epoch && syscall_status>=-4095){
  if(row->filp_returned &&
     ((row->filp_status==0 && syscall_status>=0) ||
      (row->filp_status<0 && syscall_status==row->filp_status))){
   result.observation_class=SQ515_DIRECT_FILP_OBSERVED;
   result.filp_status=row->filp_status;result.complete=true;
  }else if(!row->filp_entered && syscall_status<0){
   // For example getname/get_unused_fd_flags failure. No filename or
   // do_filp_open observation is invented from this earlier syscall failure.
   result.observation_class=SQ515_DIRECT_BEFORE_FILP_FAILURE;
   result.complete=true;
  }
 }
 memset(row,0,sizeof(*row));return result;
}
static inline void sq515_direct_exit(struct sq515_direct_table *table,
                                     const struct sq515_task_identity *task)
{
 int slot=sq515_direct_find(table,task);
 if(slot>=0 && sq515_same_identity(&table->entries[slot].key.task,task))
  memset(&table->entries[slot],0,sizeof(table->entries[slot]));
}
#endif
