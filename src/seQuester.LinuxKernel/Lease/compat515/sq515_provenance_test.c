/* SPDX-License-Identifier: GPL-2.0-only
 * Successful-tracepoint state tests; never attaches a kernel hook.
 */
#include <stdio.h>
#include "sq515_provenance.h"
static struct sq515_provenance_table table;
static unsigned int checks;
#define REQUIRE(x) do {if(!(x)){fprintf(stderr,"FAILED %u: %s\n",__LINE__,#x);return 1;}checks++;}while(0)
static struct sq515_task_identity actor(unsigned int pid,__u64 start,unsigned int exec)
{struct sq515_task_identity x={pid,pid,exec,start,start};return x;}
int main(void)
{
 struct sq515_task_identity original=actor(101,5000,1),identity=original,other;
 struct sq515_provenance_snapshot evidence;
 __u64 generation;
 unsigned int i;
 sq515_provenance_init(&table);
 REQUIRE(!sq515_provenance_observe(&table,&identity).clean);
 REQUIRE(sq515_provenance_commit_exec(&table,&identity,true));
 evidence=sq515_provenance_observe(&table,&identity);generation=evidence.generation;
 REQUIRE(evidence.clean && evidence.state==SQ515_CLEAN_SINGLETON && !(generation&1));
 other=identity;other.self_exec_id++;
 REQUIRE(!sq515_provenance_observe(&table,&other).clean);
 // A failed exec never emits a successful-exec commit. An early failure
 // retains the actual old image; a changed exec counter invalidates its row.
 REQUIRE(sq515_provenance_observe(&table,&original).clean);
 identity.self_exec_id++;REQUIRE(sq515_provenance_commit_exec(&table,&identity,true));
 REQUIRE(sq515_provenance_observe(&table,&identity).generation>generation);
 REQUIRE(!sq515_provenance_observe(&table,&original).clean);
 sq515_provenance_exit(&table,&original);
 sq515_provenance_taint(&table,&original,SQ515_SHARED_MM_TAINTED);
 REQUIRE(sq515_provenance_observe(&table,&identity).clean);
 other=actor(101,9000,2);REQUIRE(!sq515_provenance_observe(&table,&other).clean);
 sq515_provenance_taint(&table,&other,SQ515_SHARED_MM_TAINTED);
 REQUIRE(sq515_provenance_observe(&table,&identity).clean);
 sq515_provenance_taint(&table,&identity,SQ515_SHARED_MM_TAINTED);
 REQUIRE(!sq515_provenance_observe(&table,&identity).clean);
 REQUIRE(sq515_provenance_observe(&table,&identity).state==SQ515_SHARED_MM_TAINTED);
 identity.self_exec_id++;REQUIRE(sq515_provenance_commit_exec(&table,&identity,true));
 sq515_provenance_taint(&table,&identity,SQ515_PR_SET_MM_TAINTED);
 REQUIRE(!sq515_provenance_observe(&table,&identity).clean);
 identity.self_exec_id++;REQUIRE(sq515_provenance_commit_exec(&table,&identity,true));
 REQUIRE(sq515_provenance_observe(&table,&identity).clean);
 sq515_provenance_loss(&table);
 REQUIRE(!sq515_provenance_observe(&table,&identity).clean);
 REQUIRE(sq515_provenance_observe(&table,&identity).state==SQ515_LOSS_UNKNOWN);
 identity.self_exec_id++;REQUIRE(sq515_provenance_commit_exec(&table,&identity,true));
 REQUIRE(sq515_provenance_observe(&table,&identity).clean);
 other=actor(202,7000,10);other.tgid=101;other.process_start_ns=5000;
 REQUIRE(!sq515_provenance_commit_exec(&table,&other,true));
 // The successful tracepoint supplies the fresh post-de_thread key directly.
 // No pre-transition task pointer or kretprobe ticket supplies authority.
 other=actor(101,5000,11);
 REQUIRE(sq515_provenance_commit_exec(&table,&other,true));
 REQUIRE(sq515_provenance_observe(&table,&other).clean);
 REQUIRE(!sq515_provenance_observe(&table,&identity).clean);
 sq515_provenance_exit(&table,&identity);
 REQUIRE(sq515_provenance_observe(&table,&other).clean);
 REQUIRE(!sq515_provenance_commit_exec(&table,&other,false));
 REQUIRE(!sq515_provenance_observe(&table,&other).clean);
 REQUIRE(sq515_provenance_commit_exec(&table,&other,true));
 identity=actor(303,15000,2);REQUIRE(sq515_provenance_commit_exec(&table,&identity,true));
 sq515_provenance_loss(&table);
 REQUIRE(!sq515_provenance_observe(&table,&identity).clean);
 REQUIRE(!sq515_provenance_observe(&table,&other).clean);
 sq515_provenance_exit(&table,&other);
 REQUIRE(!sq515_provenance_observe(&table,&other).clean);
 identity=actor(0,0,0);REQUIRE(!sq515_provenance_commit_exec(&table,&identity,true));
 identity=actor(333,12345,0);REQUIRE(!sq515_provenance_commit_exec(&table,&identity,true));
 sq515_provenance_init(&table);
 for(i=0;i<SQ515_PROVENANCE_SLOTS;i++){
  identity=actor(1000+i,100000+i,1);
  REQUIRE(sq515_provenance_commit_exec(&table,&identity,true));
 }
 identity=actor(9000,900000,1);REQUIRE(!sq515_provenance_commit_exec(&table,&identity,true));
 other=actor(1000,100000,1);REQUIRE(!sq515_provenance_observe(&table,&other).clean);
 sq515_provenance_init(&table);generation=0;
 for(i=0;i<10000;i++){
  identity=actor(101,5000+i,1);REQUIRE(sq515_provenance_commit_exec(&table,&identity,true));
  evidence=sq515_provenance_observe(&table,&identity);
  REQUIRE(evidence.clean && evidence.generation>generation);generation=evidence.generation;
  sq515_provenance_exit(&table,&identity);
  REQUIRE(!sq515_provenance_observe(&table,&identity).clean);
 }
 table.next_generation=~(__u64)0-1;
 REQUIRE(!sq515_provenance_commit_exec(&table,&identity,true) && table.disabled);
 sq515_provenance_init(&table);table.loss_epoch=~(__u64)0;
 sq515_provenance_loss(&table);REQUIRE(table.disabled);
 printf("{\"Passed\":true,\"Checks\":%u,\"KernelHooksAttached\":false,\"RuntimeCaptureQualified\":false,\"Profile\":\"SUCCESSFUL_EXEC_TRACEPOINT_STATE\",\"ProcessLifecycleCycles\":10000}\n",checks);
 return 0;
}
