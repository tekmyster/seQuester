#define _GNU_SOURCE
// SPDX-License-Identifier: GPL-2.0-only
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include "lease_event.h"
static volatile sig_atomic_t stopped;
static void stop(int signal){(void)signal;stopped=1;}
static int utf8(const unsigned char *s,size_t n)
{
 for(size_t i=0;i<n;) {
  unsigned char c=s[i++];unsigned int more=0,lo=0x80,hi=0xbf;
  if(c<0x80)continue;
  if(c>=0xc2 && c<=0xdf)more=1;
  else if(c>=0xe0 && c<=0xef){more=2;if(c==0xe0)lo=0xa0;if(c==0xed)hi=0x9f;}
  else if(c>=0xf0 && c<=0xf4){more=3;if(c==0xf0)lo=0x90;if(c==0xf4)hi=0x8f;}
  else return 0;
  if(n-i<more || s[i]<lo || s[i]>hi)return 0;
  i++;for(unsigned int k=1;k<more;k++,i++)if(s[i]<0x80 || s[i]>0xbf)return 0;
 }
 return 1;
}
static void json_string(const unsigned char *s,size_t n)
{
 putchar('"');
 for(size_t i=0;i<n;i++) {
  unsigned char c=s[i];
  if(c=='"' || c=='\\'){putchar('\\');putchar(c);}
  else if(c<0x20)printf("\\u%04x",c);
  else putchar(c);
 }
 putchar('"');
}
static void base64(const unsigned char *s,size_t n)
{
 const char *alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
 putchar('"');
 for(size_t i=0;i<n;i+=3) {
  unsigned int x=(unsigned int)s[i]<<16;if(i+1<n)x|=(unsigned int)s[i+1]<<8;if(i+2<n)x|=s[i+2];
  putchar(alphabet[x>>18]);putchar(alphabet[(x>>12)&63]);putchar(i+1<n?alphabet[(x>>6)&63]:'=');putchar(i+2<n?alphabet[x&63]:'=');
 }
 putchar('"');
}
static void path_json(const char *name,const char *path,int result)
{
 int captured=result>0 && result<=4096 && path[result-1]==0 && (size_t)(result-1)==strnlen(path,4096);
 int valid=captured && utf8((const unsigned char *)path,result-1);
 printf(",\"%sPathResult\":%d,\"%sPath\":",name,result,name);
 if(valid)json_string((const unsigned char *)path,result-1);else printf("null");
 printf(",\"%sPathStatus\":\"%s\",\"%sPathBytesBase64\":",name,captured?(valid?"captured":"invalid_utf8"):"unavailable",name);
 if(captured)base64((const unsigned char *)path,result-1);else printf("null");
}
static int event(void *context,void *data,size_t size)
{
 struct lease_event expanded={};struct lease_header *e=&expanded.h;(void)context;
 if(size!=sizeof(expanded) && size!=sizeof(*e))return -EINVAL;
 memcpy(&expanded,data,size);
 if(size==sizeof(*e) && !e->capture_issue)return -EINVAL;
 char principal[6][16];__u32 values[]={e->uid,e->euid,e->fsuid,e->gid,e->egid,e->fsgid};
 for(int n=0;n<6;n++){if(e->credential_fields&(1u<<n))snprintf(principal[n],sizeof(principal[n]),"%u",values[n]);else strcpy(principal[n],"null");}
#ifdef SQ_CONTROLLED_V2
 const unsigned int schema_version=6;
#else
 const unsigned int schema_version=5;
#endif
 printf("{\"schemaVersion\":%u,\"cookie\":%llu,\"providerEpoch\":%llu,\"lease\":%lld,\"reservation\":%lld,\"finalizeError\":%lld,\"negativeResult\":%lld,"
  "\"pid\":%u,\"tid\":%u,\"uid\":%s,\"euid\":%s,\"fsuid\":%s,\"gid\":%s,\"egid\":%s,\"fsgid\":%s,"
  "\"taskStartNs\":%llu,\"processStartNs\":%llu,\"selfExecId\":%llu,\"before\":%llu,\"after\":%llu,"
  "\"errorBefore\":%d,\"errorAfter\":%d,\"associationError\":%d,\"priorResult\":%d,"
  "\"actorInode\":%llu,\"actorDevice\":%u,\"actorSize\":%llu,\"testMode\":%u,\"captureStartNs\":%llu,\"captureEndNs\":%llu,"
  "\"credentialFields\":%u,\"credentialError\":%d,\"whitelistEligible\":false",
  schema_version,e->cookie,e->epoch,e->lease,e->reservation,e->finalize_error,e->negative_result,
  (uint32_t)(e->pid_tid>>32),(uint32_t)e->pid_tid,principal[0],principal[1],principal[2],principal[3],principal[4],principal[5],
  e->task_start_ns,e->process_start_ns,e->self_exec_id,e->before,e->after,
  e->error_before,e->error_after,e->association_error,e->prior_result,e->actor_inode,e->actor_device,e->actor_size,e->mode,e->capture_start_ns,e->capture_end_ns,e->credential_fields,e->credential_error);
#ifdef SQ_CONTROLLED_V2
 printf(",\"targetInode\":%llu,\"targetDevice\":%u,\"targetOrdinal\":%u",e->target_inode,e->target_device,e->target_ordinal);
#endif
 const char *issues[]={"NONE","SCRATCH_UNAVAILABLE","SCRATCH_REENTRANT","SCRATCH_LOST_AFTER_CAPTURE","SCRATCH_LOST_AFTER_FINALIZE","SEQUENCE_UNAVAILABLE"};
 const char *issue=e->capture_issue<6?issues[e->capture_issue]:"UNKNOWN_CAPTURE_ISSUE";
 printf(",\"captureIssue\":\"%s\",\"recordForm\":\"%s\",\"pathSemantics\":\"LINUX_D_PATH_CURRENT_TASK_FS_ROOT\",\"mountNamespaceIdentity\":null,\"mountNamespaceIdentityStatus\":\"NOT_CAPTURED\",\"originalSyscallPathStatus\":\"UNAVAILABLE_FROM_RESOLVED_FILE_PATH\",\"deletedPathTextStatus\":\"POSSIBLY_PRESENT_AND_AMBIGUOUS\",\"credentialNamespace\":\"INITIAL_USER_NAMESPACE\",\"credentialIdEncoding\":\"KERNEL_GLOBAL_KUID_KGID\",\"targetOperationOutcome\":\"not-observed\",\"priorResultMeaning\":\"PRECEDING_BPF_LSM_RESULT\",\"actorPathRenderedAtNs\":",issue,size==sizeof(*e)?"compact":"full");
 if(e->actor_path_rendered_ns)printf("%llu",e->actor_path_rendered_ns);else printf("null");
 printf(",\"targetPathRenderedAtNs\":");if(e->target_path_rendered_ns)printf("%llu",e->target_path_rendered_ns);else printf("null");
 path_json("actor",expanded.actor_path,e->actor_path_result);path_json("target",expanded.target_path,e->target_path_result);puts("}");
 fflush(stdout);return 0;
}
#ifndef SQ_CONTROLLED_V2
static int diagnostic_main(int argc,char **argv)
{
 /* file_open execution is reverse attachment order on this pinned kernel. */
 const char *names[]={"sq_test_denial","sq_mm_prctl","sq_task_alloc","sq_mm_exec","observe"};
 struct bpf_object *object=NULL;struct bpf_link *links[5]={};struct ring_buffer *ring=NULL;
 struct stat st;struct lease_filter filter={};struct bpf_map_info map_info={};
 unsigned int key=0,ids[5]={},info_size=sizeof(map_info);int result=1,fd,lost_fd=-1;
 if(argc!=3)return 2;
 signal(SIGTERM,stop);signal(SIGINT,stop);
 object=bpf_object__open_file(argv[1],NULL);if(libbpf_get_error(object)){object=NULL;goto done;}
 if(bpf_object__load(object))goto done;
 /* Freeze BEFORE attachment. This blocks userspace update/delete through
  * any map FD, including an FD opened by ID, without blocking BPF helpers.
  * Fail provider admission if the actual kernel cannot enforce this. */
 int scratch_fd=bpf_object__find_map_fd_by_name(object,"event_scratch");
 struct bpf_map_info scratch_info={};unsigned int scratch_info_size=sizeof(scratch_info);
 if(scratch_fd<0 || bpf_map_freeze(scratch_fd) || bpf_obj_get_info_by_fd(scratch_fd,&scratch_info,&scratch_info_size))goto done;
 if(!strcmp(argv[2],"--load-only")){puts("LOAD_OK");result=0;goto done;}
 if(stat(argv[2],&st))goto done;
 if(getrandom(&filter.epoch,sizeof(filter.epoch),0)!=sizeof(filter.epoch) || !filter.epoch)goto done;
 filter.inode=st.st_ino;filter.device=(major(st.st_dev)<<20)|minor(st.st_dev);
 for(int n=0;n<5;n++) {
  struct bpf_program *program=bpf_object__find_program_by_name(object,names[n]);
  struct bpf_prog_info info={};unsigned int size=sizeof(info);
  if(!program)goto done;
  links[n]=bpf_program__attach_lsm(program);if(libbpf_get_error(links[n])){links[n]=NULL;goto done;}
  if(bpf_obj_get_info_by_fd(bpf_program__fd(program),&info,&size))goto done;
  ids[n]=info.id;
 }
 fd=bpf_object__find_map_fd_by_name(object,"lease_config");
 if(fd<0 || bpf_map_update_elem(fd,&key,&filter,BPF_ANY) || bpf_obj_get_info_by_fd(fd,&map_info,&info_size))goto done;
 lost_fd=bpf_object__find_map_fd_by_name(object,"lost");if(lost_fd<0)goto done;
 fd=bpf_object__find_map_fd_by_name(object,"events");ring=ring_buffer__new(fd,event,NULL,NULL);if(!ring)goto done;
 printf("{\"ready\":true,\"schemaVersion\":5,\"programId\":%u,\"programIds\":[%u,%u,%u,%u,%u],\"scratchMapFrozen\":true,\"scratchMapId\":%u,\"scratchValueSize\":%zu,\"configMapId\":%u,\"providerEpoch\":%llu,\"targetInode\":%llu,\"targetDevice\":%u}\n",
  ids[4],ids[0],ids[1],ids[2],ids[3],ids[4],scratch_info.id,sizeof(struct lease_scratch),map_info.id,filter.epoch,filter.inode,filter.device);
 fflush(stdout);result=0;
 while(!stopped){int error=ring_buffer__poll(ring,100);if(error<0 && error!=-EINTR){result=3;break;}}
done:
 // Detach observation first, then provenance hooks. Drain residual records.
 for(int n=4;n>=0;n--){bpf_link__destroy(links[n]);links[n]=NULL;}
 if(ring)ring_buffer__consume(ring);
 if(lost_fd>=0){__u64 lost=0;if(bpf_map_lookup_elem(lost_fd,&key,&lost)){result=4;}else printf("{\"complete\":true,\"lost\":%llu}\n",lost);}
 ring_buffer__free(ring);bpf_object__close(object);return result;
}

#include "controlled_loader.h"
#else
#include "controlled_v2_loader.h"
#endif
int main(int argc,char **argv)
{
#ifdef SQ_CONTROLLED_V2
 if(argc>=3&&!strcmp(argv[1],"--controlled-v2"))return controlled_v2_main(argv[2],argc-3,argv+3);
 fputs("Only --controlled-v2 object target... is accepted\n",stderr);return 2;
#else
 if(argc==4&&!strcmp(argv[1],"--controlled"))return controlled_main(argv[2],argv[3]);
 return diagnostic_main(argc,argv);
#endif
}
