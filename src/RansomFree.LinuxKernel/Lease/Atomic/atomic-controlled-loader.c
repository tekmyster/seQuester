/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#define SQ_CONTROLLED_V2
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "lease_event.h"
#include "atomic_operation_event.h"
static volatile sig_atomic_t stopped;
static void stop(int signal){(void)signal;stopped=1;}
/* Reuse the qualified EOF command and descriptor-based target pinning. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
static int event(void *context,void *data,size_t size){(void)context;(void)data;(void)size;return -ENOTSUP;}
#include "controlled_common.h"
#include "controlled_v2_targets.h"
#pragma GCC diagnostic pop
static int atomic_event(void *context,void *data,size_t size)
{
 (void)context;
 if(size!=sizeof(struct sq_operation_event) && size!=sizeof(struct sq_io_event))return -EPROTO;
 const struct sq_operation_event *observation=data;
 if(observation->struct_size!=size)return -EPROTO;
 if(size==sizeof(struct sq_io_event)?observation->hook<3 || observation->hook>4 || (observation->schema_version!=3 && observation->schema_version!=4):observation->hook<1 || observation->hook>2 || (observation->schema_version!=1 && observation->schema_version!=2))return -EPROTO;
 const unsigned char *bytes=data;const char alphabet[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
 char encoded[409];size_t output=0;
 for(size_t i=0;i<size;i+=3){unsigned int n=(unsigned int)bytes[i]<<16;
  if(i+1<size)n|=(unsigned int)bytes[i+1]<<8;
  if(i+2<size)n|=bytes[i+2];
  encoded[output++]=alphabet[(n>>18)&63];encoded[output++]=alphabet[(n>>12)&63];
  encoded[output++]=i+1<size?alphabet[(n>>6)&63]:'=';encoded[output++]=i+2<size?alphabet[n&63]:'=';
 }
 encoded[output]=0;
 if(printf("{\"schemaVersion\":%u,\"atomicObservation\":\"%s\"}\n",size==sizeof(struct sq_io_event)?8u:7u,encoded)<0||fflush(stdout)||ferror(stdout))return -EPIPE;
 return 0;
}
static int health(int fd,__u64 values[6],__u64 *sum)
{
 *sum=0;for(__u32 index=0;index<6;index++){
  if(bpf_map_lookup_elem(fd,&index,&values[index]))return -errno;
  if(~0ULL-*sum<values[index])return -EOVERFLOW;
  *sum+=values[index];
 }return 0;
}
int main(int argc,char **argv)
{
 if(argc<4||strcmp(argv[1],"--controlled-v4")){fputs("Expected --controlled-v4 object target...\n",stderr);return 2;}
 const char *names[]={"sq_mm_prctl","sq_mm_exec","sq_task_alloc","sq_inode_enter","sq_inode_leave","sq_file_enter","sq_file_leave","sq_write_enter","sq_write_leave","sq_iter_write_enter","sq_iter_write_leave"};
 const char *map_names[]={"inode_calls","op_config","op_events","op_health","op_targets","file_calls","scalar_calls","iter_calls"};
 struct bpf_object *object=NULL;struct bpf_link *links[11]={};struct bpf_program *programs[11]={};struct ring_buffer *ring=NULL;
 struct controlled_target targets[SQ_WATCH_MAX]={};for(int n=0;n<SQ_WATCH_MAX;n++)targets[n].fd=-1;
 struct bpf_map_info infos[8]={};int fds[8];for(int n=0;n<8;n++)fds[n]=-1;
 unsigned int ids[11]={},attached=0,order[11]={};__u32 zero=0;__u64 epoch=0,counters[6]={},lost=0;
 unsigned char nonce_bytes[16];char nonce[33]={},session[33]={};int result=1,native_error=0,activated=0,attempted=0;
 const char *reason="CONTROLLED_SETUP_FAILED";int count=argc-3;struct stat input;
 struct sigaction action={.sa_handler=stop};sigemptyset(&action.sa_mask);sigaction(SIGTERM,&action,NULL);sigaction(SIGINT,&action,NULL);signal(SIGPIPE,SIG_IGN);
 if(fstat(STDIN_FILENO,&input)||!S_ISFIFO(input.st_mode)){native_error=EINVAL;goto done;}
 if((native_error=controlled_pin_targets(targets,count,argv+3)))goto done;
 if((native_error=controlled_random(&epoch,sizeof(epoch)))||!epoch||(native_error=controlled_random(nonce_bytes,sizeof(nonce_bytes))))goto done;
 for(int n=0;n<16;n++){snprintf(nonce+2*n,3,"%02x",nonce_bytes[n]);}
 if(!controlled_hex(nonce,32)){native_error=EINVAL;goto done;}
 object=bpf_object__open_file(argv[2],NULL);native_error=(int)libbpf_get_error(object);if(native_error){object=NULL;goto done;}
 if((native_error=bpf_object__load(object)))goto done;
 const struct {__u32 type,key_size,value_size,entries,flags;} layouts[]={
  {BPF_MAP_TYPE_TASK_STORAGE,4,320,0,BPF_F_NO_PREALLOC},{BPF_MAP_TYPE_ARRAY,4,8,1,0},{BPF_MAP_TYPE_RINGBUF,0,0,1048576,0},
  {BPF_MAP_TYPE_ARRAY,4,8,6,0},{BPF_MAP_TYPE_HASH,16,8,32,BPF_F_RDONLY_PROG},{BPF_MAP_TYPE_TASK_STORAGE,4,320,0,BPF_F_NO_PREALLOC},{BPF_MAP_TYPE_TASK_STORAGE,4,320,0,BPF_F_NO_PREALLOC},{BPF_MAP_TYPE_TASK_STORAGE,4,320,0,BPF_F_NO_PREALLOC}};
 for(int n=0;n<8;n++){
  fds[n]=bpf_object__find_map_fd_by_name(object,map_names[n]);unsigned int size=sizeof(infos[n]);
  if(fds[n]<0||bpf_obj_get_info_by_fd(fds[n],&infos[n],&size)){native_error=errno?errno:ENOENT;goto done;}
  if(!infos[n].id||infos[n].type!=layouts[n].type||infos[n].key_size!=layouts[n].key_size||infos[n].value_size!=layouts[n].value_size||infos[n].max_entries!=layouts[n].entries||infos[n].map_flags!=layouts[n].flags){native_error=EINVAL;goto done;}
  for(int previous=0;previous<n;previous++)if(infos[previous].id==infos[n].id){native_error=EINVAL;goto done;}
 }
 if(bpf_map_freeze(fds[0])||bpf_map_freeze(fds[5])||bpf_map_freeze(fds[6])||bpf_map_freeze(fds[7])||bpf_map_update_elem(fds[1],&zero,&epoch,BPF_ANY)||bpf_map_freeze(fds[1])){native_error=errno;goto done;}
 for(int n=0;n<count;n++){struct sq_operation_watch_value value={.ordinal=(__u32)n};if(bpf_map_update_elem(fds[4],&targets[n].key,&value,BPF_NOEXIST)){native_error=errno;goto done;}}
 if(bpf_map_freeze(fds[4])){native_error=errno;goto done;}
 for(int n=0;n<11;n++){
  programs[n]=bpf_object__find_program_by_name(object,names[n]);struct bpf_prog_info info={};unsigned int size=sizeof(info);
  if(!programs[n]||bpf_obj_get_info_by_fd(bpf_program__fd(programs[n]),&info,&size)||!info.id){native_error=EINVAL;goto done;}ids[n]=info.id;
 }
 for(int n=0;n<3;n++){links[n]=bpf_program__attach_lsm(programs[n]);native_error=(int)libbpf_get_error(links[n]);if(native_error){links[n]=NULL;goto done;}order[attached++]=(unsigned int)n;}
 ring=ring_buffer__new(fds[2],atomic_event,NULL,NULL);if(!ring){native_error=errno;goto done;}
 if((native_error=health(fds[3],counters,&lost))||lost){native_error=native_error?native_error:ENODATA;goto done;}
 char ready[4097];size_t used=0;int error;
#define APPEND(...) do{error=controlled_append(ready,&used,__VA_ARGS__);if(error){native_error=error;goto done;}}while(0)
 APPEND("{\"controlledReady\":true,\"controlVersion\":4,\"schemaVersion\":8,\"loadedProgramIds\":[%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u],\"attachedProgramIds\":[%u,%u,%u],\"permissionAttached\":false,\"scratchMapFrozen\":true,\"scratchMapId\":%u,\"fileCallMapId\":%u,\"fileCallMapFrozen\":true,\"configMapFrozen\":true,\"configMapId\":%u,\"eventsMapId\":%u,\"lostMapId\":%u,\"providerEpoch\":%llu,\"activationNonce\":\"%s\",\"targetCount\":%d,\"targets\":[",ids[0],ids[1],ids[2],ids[3],ids[4],ids[5],ids[6],ids[7],ids[8],ids[9],ids[10],ids[0],ids[1],ids[2],infos[0].id,infos[5].id,infos[1].id,infos[2].id,infos[3].id,epoch,nonce,count);
 for(int n=0;n<count;n++)APPEND("%s{\"ordinal\":%d,\"device\":%u,\"inode\":%llu}",n?",":"",n,targets[n].key.device,targets[n].key.inode);
 APPEND("],\"ioAttached\":false,\"scalarCallMapId\":%u,\"scalarCallMapFrozen\":true,\"iterCallMapId\":%u,\"iterCallMapFrozen\":true",infos[6].id,infos[7].id);
 APPEND(",\"targetsPinned\":true,\"watchMapId\":%u,\"watchMapFrozen\":true,\"mode\":0,\"healthAtReady\":[0,0,0,0,0,0],\"activationFrame\":\"one-command-then-eof\"}\n",infos[4].id);
#undef APPEND
 if(fwrite(ready,1,used,stdout)!=used||fflush(stdout)||ferror(stdout)){native_error=EPIPE;goto done;}
 if((native_error=controlled_command(epoch,nonce,session)))goto done;
 close(STDIN_FILENO);
 if(stopped){native_error=EINTR;goto done;}
 attempted=1;
 const int permission_order[8]={4,6,8,10,3,5,7,9};
 for(int step=0;step<8;step++){int n=permission_order[step];links[n]=bpf_program__attach_trace(programs[n]);native_error=(int)libbpf_get_error(links[n]);if(native_error){links[n]=NULL;reason="ACTIVATION_UNKNOWN";goto done;}order[attached++]=(unsigned int)n;}
 if((native_error=health(fds[3],counters,&lost)))goto done;
 printf("{\"controlledActivated\":true,\"controlVersion\":4,\"sessionId\":\"%s\",\"providerEpoch\":%llu,\"activationNonce\":\"%s\",\"attachedProgramIds\":[%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u],\"permissionAttached\":true,\"ioAttached\":true,\"lostAtActivation\":%llu}\n",session,epoch,nonce,ids[0],ids[1],ids[2],ids[4],ids[6],ids[8],ids[10],ids[3],ids[5],ids[7],ids[9],lost);
 if(fflush(stdout)||ferror(stdout)){native_error=EPIPE;reason="ACTIVATION_UNKNOWN";goto done;}
 activated=1;result=0;reason="CONTROLLED_STOPPED";
 while(!stopped){error=ring_buffer__poll(ring,100);if(error<0&&error!=-EINTR){native_error=error;result=3;reason="CONTROLLED_STREAM_FAILED";break;}}
done:
 for(unsigned int n=attached;n>0;n--){unsigned int index=order[n-1];bpf_link__destroy(links[index]);links[index]=NULL;}
 int drained=ring?ring_buffer__consume(ring):0;if(drained<0){result=4;reason="CONTROLLED_DRAIN_UNKNOWN";}
 int health_error=fds[3]<0?ENOENT:health(fds[3],counters,&lost);
 if(health_error)printf("{\"controlledComplete\":true,\"controlVersion\":4,\"activated\":%s,\"observerAttempted\":%s,\"reason\":\"%s\",\"nativeError\":%d,\"retainedLinksDestroyed\":%u,\"drainResult\":%d,\"lost\":null,\"lostError\":%d}\n",activated?"true":"false",attempted?"true":"false",reason,native_error,attached,drained,health_error);
 else printf("{\"controlledComplete\":true,\"controlVersion\":4,\"activated\":%s,\"observerAttempted\":%s,\"reason\":\"%s\",\"nativeError\":%d,\"retainedLinksDestroyed\":%u,\"drainResult\":%d,\"lost\":%llu,\"lostError\":null}\n",activated?"true":"false",attempted?"true":"false",reason,native_error,attached,drained,lost);
 if(fflush(stdout)||ferror(stdout))result=4;
 ring_buffer__free(ring);bpf_object__close(object);for(int n=0;n<SQ_WATCH_MAX;n++)if(targets[n].fd>=0)close(targets[n].fd);
 return result;
}
