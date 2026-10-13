/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdio.h>
#include <stdlib.h>
#include "sq515_direct.h"
static unsigned long checks;
#define CHECK(x) do {checks++;if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);exit(1);}}while(0)
static struct sq515_task_identity task(unsigned int id)
{
 struct sq515_task_identity value={id,id,1,100000+id,200000+id};
 return value;
}
int main(void)
{
 struct sq515_direct_table table;
 struct sq515_task_identity a=task(101),b=a;
 struct sq515_direct_key outer,inner,stale;
 struct sq515_direct_result result;
 unsigned int i;
 sq515_direct_init(&table,0);CHECK(!sq515_direct_begin(&table,&a,&outer));
 sq515_direct_init(&table,7);
 CHECK(!sq515_direct_filp_enter(&table,&a,&inner)); // internal open
 CHECK(sq515_direct_begin(&table,&a,&outer));
 CHECK(sq515_direct_filp_enter(&table,&a,&inner));
 CHECK(sq515_direct_key_equal(&outer,&inner));
 CHECK(sq515_direct_filp_return(&table,&inner,0));
 result=sq515_direct_finish(&table,&outer,4);
 CHECK(result.complete && result.observation_class==SQ515_DIRECT_FILP_OBSERVED && result.filp_status==0);
 stale=outer;
 CHECK(sq515_direct_begin(&table,&a,&outer));
 CHECK(outer.nonce!=stale.nonce);
 result=sq515_direct_finish(&table,&stale,0);CHECK(!result.complete);
 CHECK(sq515_direct_filp_enter(&table,&a,&inner));
 CHECK(!sq515_direct_filp_return(&table,&stale,-13));
 CHECK(sq515_direct_filp_return(&table,&inner,-13));
 result=sq515_direct_finish(&table,&outer,-13);
 CHECK(result.complete && result.filp_status==-13);
 CHECK(sq515_direct_begin(&table,&a,&outer));
 result=sq515_direct_finish(&table,&outer,-14);
 CHECK(result.complete && result.observation_class==SQ515_DIRECT_BEFORE_FILP_FAILURE);
 CHECK(sq515_direct_begin(&table,&a,&outer));
 result=sq515_direct_finish(&table,&outer,5);CHECK(!result.complete);
 CHECK(sq515_direct_begin(&table,&a,&outer));
 CHECK(sq515_direct_filp_enter(&table,&a,&inner));
 CHECK(!sq515_direct_filp_return(&table,&inner,123456)); // pointer prohibited
 result=sq515_direct_finish(&table,&outer,4);CHECK(!result.complete);
 CHECK(sq515_direct_begin(&table,&a,&outer));
 CHECK(sq515_direct_filp_enter(&table,&a,&inner));
 CHECK(sq515_direct_filp_return(&table,&inner,-13));
 result=sq515_direct_finish(&table,&outer,3);CHECK(!result.complete);
 CHECK(sq515_direct_begin(&table,&a,&outer));
 CHECK(sq515_direct_filp_enter(&table,&a,&inner));
 CHECK(!sq515_direct_filp_enter(&table,&a,&stale));
 result=sq515_direct_finish(&table,&outer,0);CHECK(!result.complete);
 CHECK(sq515_direct_begin(&table,&a,&outer));
 CHECK(!sq515_direct_begin(&table,&a,&inner)); // nested outer call
 result=sq515_direct_finish(&table,&outer,-13);CHECK(!result.complete);
 CHECK(sq515_direct_begin(&table,&a,&outer));
 sq515_direct_loss(&table);
 CHECK(!sq515_direct_filp_enter(&table,&a,&inner));
 result=sq515_direct_finish(&table,&outer,-13);CHECK(!result.complete);
 CHECK(sq515_direct_begin(&table,&a,&outer));
 b.self_exec_id++;
 CHECK(!sq515_direct_filp_enter(&table,&b,&inner));
 result=sq515_direct_finish(&table,&outer,-13);CHECK(!result.complete);
 b=a;b.task_start_ns++;b.process_start_ns++;
 CHECK(sq515_direct_begin(&table,&a,&outer));sq515_direct_exit(&table,&a);
 CHECK(sq515_direct_begin(&table,&b,&inner));
 sq515_direct_exit(&table,&a);CHECK(sq515_direct_find(&table,&b)>=0);
 CHECK(!sq515_direct_finish(&table,&outer,0).complete);
 CHECK(sq515_direct_finish(&table,&inner,-13).complete);
 sq515_direct_init(&table,8);
 for(i=0;i<SQ515_DIRECT_SLOTS;i++){
  a=task(1000+i);CHECK(sq515_direct_begin(&table,&a,&outer));
 }
 a=task(9000);CHECK(!sq515_direct_begin(&table,&a,&outer));
 for(i=0;i<SQ515_DIRECT_SLOTS;i++)CHECK(table.entries[i].used && table.entries[i].ambiguous);
 sq515_direct_init(&table,9);a=task(101);
 for(i=0;i<10000;i++){
  CHECK(sq515_direct_begin(&table,&a,&outer));
  CHECK(sq515_direct_filp_enter(&table,&a,&inner));
  CHECK(sq515_direct_filp_return(&table,&inner,i%2?-13:0));
  result=sq515_direct_finish(&table,&outer,i%2?-13:3);
  CHECK(result.complete && result.key.source_epoch==9 && result.key.nonce==(unsigned long long)i+1);
  CHECK(sq515_direct_find(&table,&a)<0);
 }
 table.next_nonce=~(__u64)0;CHECK(!sq515_direct_begin(&table,&a,&outer) && table.disabled);
 sq515_direct_init(&table,10);table.loss_epoch=~(__u64)0;
 sq515_direct_loss(&table);CHECK(table.disabled);
 printf("{\"Passed\":true,\"Checks\":%lu,\"OperationCycles\":10000,\"KernelHooksAttached\":false,\"RuntimeCaptureQualified\":false,\"Profile\":\"DIRECT_OPEN_SCALAR_CORRELATION\"}\n",checks);
 return 0;
}
