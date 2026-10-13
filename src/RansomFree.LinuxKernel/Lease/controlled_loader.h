#include "controlled_common.h"
static int controlled_main(const char *object_path,const char *target_path)
{
 const char *names[]={"sq_test_denial","sq_mm_prctl","sq_task_alloc","sq_mm_exec","observe"};
 struct bpf_object *object=NULL;struct bpf_link *links[5]={};struct ring_buffer *ring=NULL;
 struct bpf_program *programs[5]={};unsigned int ids[5]={},order[5]={},attached=0,key=0;
 struct bpf_map_info config_info={},scratch_info={},events_info={},lost_info={};
 struct lease_filter filter={};struct stat input,target;unsigned char random_nonce[16];
 char nonce[33]={},session[33]={};int result=1,native_error=0,target_fd=-1,lost_fd=-1;
 int observer_attempted=0,activated=0;const char *reason="CONTROLLED_SETUP_FAILED";
 struct sigaction action={.sa_handler=stop};sigemptyset(&action.sa_mask);
 sigaction(SIGTERM,&action,NULL);sigaction(SIGINT,&action,NULL);signal(SIGPIPE,SIG_IGN);
 if(fstat(STDIN_FILENO,&input)){native_error=errno;reason="CONTROLLED_PIPE_REQUIRED";goto done;}
 if(!S_ISFIFO(input.st_mode)){native_error=EINVAL;reason="CONTROLLED_PIPE_REQUIRED";goto done;}
 /* O_PATH pins this inode across path replacement, but does not open it for
  * content or grant a later pathname lookup authority over actor bytes. */
 target_fd=open(target_path,O_PATH|O_CLOEXEC);
 if(target_fd<0){native_error=errno;goto done;}
 if(fstat(target_fd,&target)){native_error=errno;goto done;}
 if(!S_ISREG(target.st_mode)||!target.st_ino||major(target.st_dev)>4095||minor(target.st_dev)>1048575){native_error=EINVAL;goto done;}
 filter.inode=target.st_ino;filter.device=(major(target.st_dev)<<20)|minor(target.st_dev);
 if(!filter.device||(native_error=controlled_random(&filter.epoch,sizeof(filter.epoch)))||!filter.epoch||
    (native_error=controlled_random(random_nonce,sizeof(random_nonce))))goto done;
 for(size_t n=0;n<sizeof(random_nonce);n++)snprintf(nonce+2*n,3,"%02x",random_nonce[n]);
 if(!controlled_hex(nonce,32)){native_error=EINVAL;goto done;}
 object=bpf_object__open_file(object_path,NULL);native_error=(int)libbpf_get_error(object);
 if(native_error){object=NULL;goto done;}
 if((native_error=bpf_object__load(object)))goto done;
 int scratch_fd=bpf_object__find_map_fd_by_name(object,"event_scratch"),config_fd=bpf_object__find_map_fd_by_name(object,"lease_config");
 int events_fd=bpf_object__find_map_fd_by_name(object,"events");lost_fd=bpf_object__find_map_fd_by_name(object,"lost");
 if(scratch_fd<0||config_fd<0||events_fd<0||lost_fd<0){native_error=ENOENT;goto done;}
 if(bpf_map_freeze(scratch_fd)||bpf_map_update_elem(config_fd,&key,&filter,BPF_ANY)||bpf_map_freeze(config_fd)){native_error=errno;goto done;}
 int map_fds[]={scratch_fd,config_fd,events_fd,lost_fd};struct bpf_map_info *infos[]={&scratch_info,&config_info,&events_info,&lost_info};
 for(int n=0;n<4;n++){unsigned int size=sizeof(*infos[n]);if(bpf_obj_get_info_by_fd(map_fds[n],infos[n],&size)){native_error=errno;goto done;}}
 for(int n=0;n<5;n++){
  programs[n]=bpf_object__find_program_by_name(object,names[n]);struct bpf_prog_info info={};unsigned int size=sizeof(info);
  if(!programs[n]){native_error=ENOENT;goto done;}
  if(bpf_obj_get_info_by_fd(bpf_program__fd(programs[n]),&info,&size)){native_error=errno;goto done;}ids[n]=info.id;
 }
 /* Only provenance hooks exist at ready. Neither file_open program has a link. */
 for(int n=1;n<=3;n++){
  links[n]=bpf_program__attach_lsm(programs[n]);native_error=(int)libbpf_get_error(links[n]);
  if(native_error){links[n]=NULL;goto done;}order[attached++]=(unsigned int)n;
 }
 ring=ring_buffer__new(events_fd,controlled_event,NULL,NULL);if(!ring){native_error=errno;goto done;}
 __u64 lost=0;if(bpf_map_lookup_elem(lost_fd,&key,&lost)){native_error=errno;reason="CONTROLLED_LOST_COUNTER_UNAVAILABLE";goto done;}
 printf("{\"controlledReady\":true,\"controlVersion\":1,\"schemaVersion\":5,\"loadedProgramIds\":[%u,%u,%u,%u,%u],\"attachedProgramIds\":[%u,%u,%u],\"observeAttached\":false,\"denialAttached\":false,\"scratchMapFrozen\":true,\"scratchMapId\":%u,\"configMapFrozen\":true,\"configMapId\":%u,\"eventsMapId\":%u,\"lostMapId\":%u,\"providerEpoch\":%llu,\"activationNonce\":\"%s\",\"targetInode\":%llu,\"targetDevice\":%u,\"targetPinned\":true,\"mode\":0,\"lostAtReady\":%llu,\"activationFrame\":\"one-command-then-eof\"}\n",
  ids[0],ids[1],ids[2],ids[3],ids[4],ids[1],ids[2],ids[3],scratch_info.id,config_info.id,events_info.id,lost_info.id,filter.epoch,nonce,filter.inode,filter.device,lost);
 if(fflush(stdout)||ferror(stdout)){native_error=EPIPE;reason="CONTROLLED_READY_OUTPUT_FAILED";goto done;}
 if((native_error=controlled_command(filter.epoch,nonce,session))){reason="CONTROLLED_ACTIVATION_REJECTED";goto done;}
 close(STDIN_FILENO);
 if(stopped){native_error=EINTR;reason="CONTROLLED_ACTIVATION_REJECTED";goto done;}
 const int activation_order[]={0,4};
 for(int i=0;i<2;i++){
  int n=activation_order[i];if(n==4)observer_attempted=1;
  links[n]=bpf_program__attach_lsm(programs[n]);native_error=(int)libbpf_get_error(links[n]);
  if(native_error){links[n]=NULL;reason=observer_attempted?"ACTIVATION_UNKNOWN":"ACTIVATION_ATTACH_FAILED_NO_OBSERVER";goto done;}order[attached++]=(unsigned int)n;
 }
 if(bpf_map_lookup_elem(lost_fd,&key,&lost)){native_error=errno;reason="ACTIVATION_UNKNOWN";goto done;}
 /* Records can already exist; source admission must precede its pipe write. */
 printf("{\"controlledActivated\":true,\"controlVersion\":1,\"sessionId\":\"%s\",\"providerEpoch\":%llu,\"activationNonce\":\"%s\",\"attachedProgramIds\":[%u,%u,%u,%u,%u],\"observeAttached\":true,\"denialAttached\":true,\"lostAtActivation\":%llu}\n",session,filter.epoch,nonce,ids[1],ids[2],ids[3],ids[0],ids[4],lost);
 if(fflush(stdout)||ferror(stdout)){native_error=EPIPE;reason="ACTIVATION_UNKNOWN";goto done;}
 activated=1;result=0;reason="CONTROLLED_STOPPED";
 while(!stopped){int error=ring_buffer__poll(ring,100);if(error<0&&error!=-EINTR){native_error=error;reason="CONTROLLED_STREAM_FAILED";result=3;break;}}
done:
 /* Reverse actual attachment order, including partially activated sessions. */
 for(unsigned int n=attached;n>0;n--){unsigned int index=order[n-1];bpf_link__destroy(links[index]);links[index]=NULL;}
 int drained=ring?ring_buffer__consume(ring):0;if(drained<0){if(!native_error)native_error=drained;result=4;reason=observer_attempted?"CONTROLLED_DRAIN_UNKNOWN":reason;}
 __u64 final_lost=0;int lost_error=lost_fd<0?ENOENT:0;
 if(lost_fd>=0&&bpf_map_lookup_elem(lost_fd,&key,&final_lost))lost_error=errno;
 if(lost_error)result=4;
 printf("{\"controlledComplete\":true,\"controlVersion\":1,\"activated\":%s,\"observerAttempted\":%s,\"reason\":\"%s\",\"nativeError\":%d,\"retainedLinksDestroyed\":%u,\"drainResult\":%d,\"lost\":",activated?"true":"false",observer_attempted?"true":"false",reason,native_error,attached,drained);
 if(lost_error)printf("null,\"lostError\":%d",lost_error);else printf("%llu,\"lostError\":null",final_lost);
 puts("}");if(fflush(stdout)||ferror(stdout))result=5;
 ring_buffer__free(ring);bpf_object__close(object);if(target_fd>=0)close(target_fd);return result;
}
