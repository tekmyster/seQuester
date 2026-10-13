/* SPDX-License-Identifier: GPL-2.0-only
 * Bounded provenance state for the separate Linux 5.15 provider.
 * The native caller must hold its IRQ-safe lock for every method. This header
 * retains only scalar identities, never task/mm/file or kretprobe pointers.
 * An absent entry is unknown. Only the registered successful sched_process_exec
 * tracepoint may commit a clean generation, using fresh post-de_thread scalar
 * identity and a contemporaneous mm_users singleton check. An intermediate
 * exec-function return is never proof that the binary-handler loop succeeded.
 */
#ifndef SQ515_PROVENANCE_H
#define SQ515_PROVENANCE_H
#include <linux/types.h>
#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <stdbool.h>
#include <string.h>
#endif
#define SQ515_PROVENANCE_SLOTS 256
enum sq515_provenance_state {
 SQ515_STARTUP_UNKNOWN=1, SQ515_EXEC_IN_FLIGHT=2, SQ515_CLEAN_SINGLETON=3,
 SQ515_SHARED_MM_TAINTED=4, SQ515_PR_SET_MM_TAINTED=5,
 SQ515_LOSS_UNKNOWN=6, SQ515_NONLEADER_EXEC_UNKNOWN=7,
 SQ515_EXEC_FAILED=8, SQ515_CAPACITY_UNKNOWN=9
};
struct sq515_task_identity {
 __u32 tgid,tid,self_exec_id;
 __u64 process_start_ns,task_start_ns;
};
struct sq515_provenance_entry {
 struct sq515_task_identity identity;
 __u64 generation,loss_epoch;
 __u32 state;
 bool used;
};
struct sq515_provenance_table {
 struct sq515_provenance_entry entries[SQ515_PROVENANCE_SLOTS];
 __u64 loss_epoch,next_generation;
 bool disabled;
};
struct sq515_provenance_snapshot {
 __u64 generation,loss_epoch;
 __u32 state;
 bool clean;
};
static inline bool sq515_same_lifetime(const struct sq515_task_identity *a,
                                     const struct sq515_task_identity *b)
{return a->tid==b->tid && a->task_start_ns==b->task_start_ns;}
static inline bool sq515_same_identity(const struct sq515_task_identity *a,
                                     const struct sq515_task_identity *b)
{return sq515_same_lifetime(a,b) && a->tgid==b->tgid &&
 a->process_start_ns==b->process_start_ns && a->self_exec_id==b->self_exec_id;}
static inline bool sq515_identity_valid(const struct sq515_task_identity *a)
{return a->tid && a->tgid && a->task_start_ns && a->process_start_ns;}
static inline void sq515_provenance_init(struct sq515_provenance_table *table)
{memset(table,0,sizeof(*table));table->loss_epoch=1;}
static inline void sq515_provenance_loss(struct sq515_provenance_table *table)
{
 if(table->loss_epoch==~(__u64)0){table->disabled=true;return;}
 table->loss_epoch++;
}
static inline int sq515_provenance_find(struct sq515_provenance_table *table,
                                      const struct sq515_task_identity *identity)
{
 unsigned int i;
 for(i=0;i<SQ515_PROVENANCE_SLOTS;i++)
  if(table->entries[i].used && sq515_same_lifetime(&table->entries[i].identity,identity))return (int)i;
 return -1;
}
static inline struct sq515_provenance_snapshot sq515_provenance_observe(
 struct sq515_provenance_table *table,const struct sq515_task_identity *identity)
{
 struct sq515_provenance_snapshot result={0,table->loss_epoch,SQ515_STARTUP_UNKNOWN,false};
 int slot=sq515_provenance_find(table,identity);
 struct sq515_provenance_entry *entry;
 if(table->disabled){result.state=SQ515_LOSS_UNKNOWN;return result;}
 if(slot<0)return result;
 entry=&table->entries[slot];result.state=entry->state;
 if(entry->state!=SQ515_CLEAN_SINGLETON)return result;
 if(entry->loss_epoch!=table->loss_epoch || !sq515_same_identity(&entry->identity,identity)){
  result.state=SQ515_LOSS_UNKNOWN;return result;
 }
 result.generation=entry->generation;result.clean=entry->generation!=0;
 return result;
}
static inline bool sq515_provenance_commit_exec(
 struct sq515_provenance_table *table,const struct sq515_task_identity *identity,bool singleton)
{
 struct sq515_provenance_entry *entry;
 int slot=sq515_provenance_find(table,identity);
 unsigned int i;
 if(table->disabled || !sq515_identity_valid(identity) || !identity->self_exec_id)return false;
 if(!singleton || identity->tid!=identity->tgid){
  if(slot>=0)table->entries[slot].state=SQ515_SHARED_MM_TAINTED;
  return false;
 }
 if(slot<0)for(i=0;i<SQ515_PROVENANCE_SLOTS;i++)if(!table->entries[i].used){slot=(int)i;break;}
 if(slot<0){sq515_provenance_loss(table);return false;}
 if(table->next_generation>~(__u64)0-2){table->disabled=true;return false;}
 table->next_generation+=2;
 entry=&table->entries[slot];memset(entry,0,sizeof(*entry));
 entry->used=true;entry->identity=*identity;entry->generation=table->next_generation;
 entry->state=SQ515_CLEAN_SINGLETON;entry->loss_epoch=table->loss_epoch;
 return true;
}
static inline void sq515_provenance_taint(struct sq515_provenance_table *table,
 const struct sq515_task_identity *identity,__u32 reason)
{
 int slot=sq515_provenance_find(table,identity);
 if(reason!=SQ515_SHARED_MM_TAINTED && reason!=SQ515_PR_SET_MM_TAINTED){sq515_provenance_loss(table);return;}
 if(slot>=0 && sq515_same_identity(&table->entries[slot].identity,identity))table->entries[slot].state=reason;
}
static inline void sq515_provenance_exit(struct sq515_provenance_table *table,
 const struct sq515_task_identity *identity)
{
 int slot=sq515_provenance_find(table,identity);
 if(slot>=0 && sq515_same_identity(&table->entries[slot].identity,identity))memset(&table->entries[slot],0,sizeof(table->entries[slot]));
}
#endif
