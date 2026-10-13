/* SPDX-License-Identifier: GPL-2.0-only */
#include "controlled_common.h"
#include "controlled_v2_targets.h"
static int controlled_v2_main(const char *object_path,int target_count,char **target_paths)
{
 const char *names[]={"sq_test_denial","sq_mm_prctl","sq_task_alloc","sq_mm_exec","observe"};
 struct bpf_object *object=NULL;struct bpf_link *links[5]={};struct ring_buffer *ring=NULL;
 struct bpf_program *programs[5]={};unsigned int ids[5]={},order[5]={},attached=0,key=0;
 struct bpf_map_info infos[5]={};
 struct lease_filter filter={};struct stat input;unsigned char random_nonce[16];
 struct controlled_target targets[SQ_WATCH_MAX]={};
 for(int n=0;n<SQ_WATCH_MAX;n++)targets[n].fd=-1;
 char nonce[33]={},session[33]={};int result=1,native_error=0,lost_fd=-1;
 int observer_attempted=0,activated=0;const char *reason="CONTROLLED_SETUP_FAILED";
 struct sigaction action={.sa_handler=stop};sigemptyset(&action.sa_mask);
 sigaction(SIGTERM,&action,NULL);sigaction(SIGINT,&action,NULL);signal(SIGPIPE,SIG_IGN);
 if(fstat(STDIN_FILENO,&input)){native_error=errno;reason="CONTROLLED_PIPE_REQUIRED";goto done;}
 if(!S_ISFIFO(input.st_mode)){native_error=EINVAL;reason="CONTROLLED_PIPE_REQUIRED";goto done;}
 /* The immutable revision pins each accepted identity until all links detach. */
 if((native_error=controlled_pin_targets(targets,target_count,target_paths))){reason="CONTROLLED_TARGET_SET_REJECTED";goto done;}
 if((native_error=controlled_random(&filter.epoch,sizeof(filter.epoch)))||!filter.epoch||
    (native_error=controlled_random(random_nonce,sizeof(random_nonce))))goto done;
 for(size_t n=0;n<sizeof(random_nonce);n++)snprintf(nonce+2*n,3,"%02x",random_nonce[n]);
 if(!controlled_hex(nonce,32)){native_error=EINVAL;goto done;}
 object=bpf_object__open_file(object_path,NULL);native_error=(int)libbpf_get_error(object);
 if(native_error){object=NULL;goto done;}
 if((native_error=bpf_object__load(object)))goto done;
 int scratch_fd=bpf_object__find_map_fd_by_name(object,"event_scratch"),config_fd=bpf_object__find_map_fd_by_name(object,"lease_config");
 int watch_fd=bpf_object__find_map_fd_by_name(object,"watched_targets");
 int events_fd=bpf_object__find_map_fd_by_name(object,"events");lost_fd=bpf_object__find_map_fd_by_name(object,"lost");
 if(scratch_fd<0||config_fd<0||events_fd<0||lost_fd<0||watch_fd<0){native_error=ENOENT;goto done;}
 if(bpf_map_freeze(scratch_fd)||bpf_map_update_elem(config_fd,&key,&filter,BPF_ANY)||bpf_map_freeze(config_fd)){native_error=errno;goto done;}
 for(int n=0;n<target_count;n++){
  struct lease_watch_value value={.ordinal=(__u32)n,.reserved=0};
  if(bpf_map_update_elem(watch_fd,&targets[n].key,&value,BPF_NOEXIST)){native_error=errno;goto done;}
 }
 if(bpf_map_freeze(watch_fd)){native_error=errno;goto done;}
 int map_fds[]={scratch_fd,config_fd,events_fd,lost_fd,watch_fd};
 for(int n=0;n<5;n++){unsigned int size=sizeof(infos[n]);if(bpf_obj_get_info_by_fd(map_fds[n],&infos[n],&size)){native_error=errno;goto done;}}
 /* Validate the four inherited map layouts as well as the v2 watch table.
  * A recognized name/ID alone cannot establish a compatible native layout. */
 const struct {__u32 type,key_size,value_size,max_entries,map_flags;} expected_maps[]={
  {BPF_MAP_TYPE_TASK_STORAGE,sizeof(__u32),sizeof(struct lease_scratch),0,BPF_F_NO_PREALLOC},
  {BPF_MAP_TYPE_ARRAY,sizeof(__u32),sizeof(struct lease_filter),1,0},
  {BPF_MAP_TYPE_RINGBUF,0,0,1048576,0},
  {BPF_MAP_TYPE_ARRAY,sizeof(__u32),sizeof(__u64),1,0}
 };
 for(int n=0;n<4;n++){
  if(!infos[n].id||infos[n].type!=expected_maps[n].type||infos[n].key_size!=expected_maps[n].key_size||infos[n].value_size!=expected_maps[n].value_size||infos[n].max_entries!=expected_maps[n].max_entries||infos[n].map_flags!=expected_maps[n].map_flags){native_error=EINVAL;reason="CONTROLLED_MAP_LAYOUT_REJECTED";goto done;}
 }
 if(infos[4].type!=BPF_MAP_TYPE_HASH||infos[4].key_size!=sizeof(struct lease_watch_key)||infos[4].value_size!=sizeof(struct lease_watch_value)||infos[4].max_entries!=SQ_WATCH_MAX||infos[4].map_flags!=BPF_F_RDONLY_PROG){native_error=EINVAL;goto done;}
 for(int n=0;n<5;n++)for(int j=0;j<n;j++)if(infos[n].id==infos[j].id){native_error=EINVAL;reason="CONTROLLED_MAP_LAYOUT_REJECTED";goto done;}
 for(int n=0;n<target_count;n++){
  struct lease_watch_value value={};
  if(bpf_map_lookup_elem(watch_fd,&targets[n].key,&value)){native_error=errno;goto done;}
  if(value.ordinal!=(__u32)n||value.reserved){native_error=EINVAL;goto done;}
 }
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
 char ready[4097];int ready_length=controlled_ready_v2(ready,ids,infos,&filter,nonce,targets,target_count,lost);
 if(ready_length<0){native_error=ready_length;reason="CONTROLLED_READY_SIZE_REJECTED";goto done;}
 if(fwrite(ready,1,(size_t)ready_length,stdout)!=(size_t)ready_length){native_error=EPIPE;reason="CONTROLLED_READY_OUTPUT_FAILED";goto done;}
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
 printf("{\"controlledActivated\":true,\"controlVersion\":2,\"sessionId\":\"%s\",\"providerEpoch\":%llu,\"activationNonce\":\"%s\",\"attachedProgramIds\":[%u,%u,%u,%u,%u],\"observeAttached\":true,\"denialAttached\":true,\"lostAtActivation\":%llu}\n",session,filter.epoch,nonce,ids[1],ids[2],ids[3],ids[0],ids[4],lost);
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
 printf("{\"controlledComplete\":true,\"controlVersion\":2,\"activated\":%s,\"observerAttempted\":%s,\"reason\":\"%s\",\"nativeError\":%d,\"retainedLinksDestroyed\":%u,\"drainResult\":%d,\"lost\":",activated?"true":"false",observer_attempted?"true":"false",reason,native_error,attached,drained);
 if(lost_error)printf("null,\"lostError\":%d",lost_error);else printf("%llu,\"lostError\":null",final_lost);
 puts("}");if(fflush(stdout)||ferror(stdout))result=5;
 ring_buffer__free(ring);bpf_object__close(object);
 for(int n=0;n<SQ_WATCH_MAX;n++)if(targets[n].fd>=0)close(targets[n].fd);
 return result;
}
