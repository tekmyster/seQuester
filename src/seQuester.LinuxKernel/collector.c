#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "protocol.h"
static volatile sig_atomic_t stopped;
static FILE *output;
static void stop(int signal){(void)signal;stopped=1;}
static void text(const char *value,size_t max){
 fputc('"',output);for(size_t i=0;i<max&&value[i];i++){unsigned char c=value[i];if(c=='"'||c=='\\'){fputc('\\',output);fputc(c,output);}else if(c<32||c>=127)fprintf(output,"\\u%04x",c);else fputc(c,output);}fputc('"',output);
}
static int event(void *ctx,void *data,size_t size){
 (void)ctx;if(size!=sizeof(struct sq_event))return -EINVAL;
 const struct sq_event *e=data;
 fprintf(output,"{\"kind\":\"file\",\"sequence\":%llu,\"observedNs\":%llu,\"processStartNs\":%llu,\"pid\":%u,\"tid\":%u,\"ppid\":%u,\"uid\":%u,\"euid\":%u,\"fsuid\":%u,\"loginuid\":%u,\"openerFsuid\":%u,\"device\":%u,\"inode\":%llu,\"exeDevice\":%u,\"exeInode\":%llu,\"cgroupId\":%llu,\"operation\":%u,\"stage\":%u,\"result\":%lld,\"mask\":%u,\"flags\":%u,\"comm\":",e->sequence,e->observed_ns,e->process_start_ns,e->pid,e->tid,e->ppid,e->uid,e->euid,e->fsuid,e->loginuid,e->opener_fsuid,e->device,e->inode,e->exe_device,e->exe_inode,e->cgroup_id,e->operation,e->stage,e->result,e->mask,e->flags);
 text(e->comm,sizeof(e->comm));fputs(",\"exeName\":",output);text(e->exe_name,sizeof(e->exe_name));fputs(",\"image\":",output);text(e->image,sizeof(e->image));fputs(",\"path\":",output);text(e->path,sizeof(e->path));fputs(",\"fileName\":",output);text(e->file_name,sizeof(e->file_name));fputs("}\n",output);fflush(output);return 0;
}
int main(int argc,char **argv){
 if(argc<5||geteuid()!=0){fprintf(stderr,"Arguments: BPF object, output JSONL, duration seconds, watched files... (root required)\n");return 2;}
 struct rlimit limit={RLIM_INFINITY,RLIM_INFINITY};if(setrlimit(RLIMIT_MEMLOCK,&limit)){perror("memlock");return 2;}
 signal(SIGTERM,stop);signal(SIGINT,stop);
 struct bpf_object *object=bpf_object__open_file(argv[1],NULL);
 if(libbpf_get_error(object)){fprintf(stderr,"BPF open failed\n");return 3;}
 if(bpf_object__load(object)){fprintf(stderr,"BPF load failed\n");bpf_object__close(object);return 4;}
 int watched=bpf_object__find_map_fd_by_name(object,"watched");
 for(int i=4;i<argc;i++){struct stat s;if(stat(argv[i],&s)){perror("stat watched");return 5;}struct sq_key key={.inode=s.st_ino,.device=(major(s.st_dev)<<20)|minor(s.st_dev)};unsigned int value=1;if(bpf_map_update_elem(watched,&key,&value,BPF_ANY)){perror("watch map");return 5;}}
 struct bpf_link *links[32]={0};int count=0;struct bpf_program *program;
 bpf_object__for_each_program(program,object){if(count>=32)return 6;links[count]=bpf_program__attach(program);if(libbpf_get_error(links[count])){fprintf(stderr,"Attach failed: %s\n",bpf_program__name(program));links[count]=NULL;stopped=1;break;}count++;}
 if(stopped){for(int i=0;i<count;i++)bpf_link__destroy(links[i]);bpf_object__close(object);return 6;}
 output=fopen(argv[2],"wx");if(!output){perror("output");return 7;}
 struct ring_buffer *ring=ring_buffer__new(bpf_object__find_map_fd_by_name(object,"events"),event,NULL,NULL);
 if(!ring){fprintf(stderr,"Ring buffer failed\n");return 8;}
 char host[256]={0};gethostname(host,sizeof(host)-1);
 char boot[64]={0};FILE *bootfile=fopen("/proc/sys/kernel/random/boot_id","r");if(bootfile){if(fgets(boot,sizeof(boot),bootfile))boot[strcspn(boot,"\r\n")]=0;fclose(bootfile);}
 struct timespec realtime,boottime;clock_gettime(CLOCK_REALTIME,&realtime);clock_gettime(CLOCK_BOOTTIME,&boottime);
 long long offset=(realtime.tv_sec-boottime.tv_sec)*1000000000LL+realtime.tv_nsec-boottime.tv_nsec;
 fputs("{\"kind\":\"ready\",\"host\":",output);text(host,sizeof(host));fputs(",\"bootId\":",output);text(boot,sizeof(boot));fprintf(output,",\"realtimeOffsetNs\":%lld,\"hooks\":%d,\"eventBytes\":%zu}\n",offset,count,sizeof(struct sq_event));fflush(output);
 time_t until=time(NULL)+atoi(argv[3]),last=0;int error=0;
 while(!stopped&&time(NULL)<until){int result=ring_buffer__poll(ring,100);if(result<0&&result!=-EINTR){error=9;break;}if(time(NULL)!=last){last=time(NULL);unsigned int key=0;struct sq_counters c={0};if(bpf_map_lookup_elem(bpf_object__find_map_fd_by_name(object,"counters"),&key,&c)){error=10;break;}fprintf(output,"{\"kind\":\"health\",\"sequence\":%llu,\"dropped\":%llu}\n",c.sequence,c.dropped);fflush(output);}}
 for(int i=0;i<count;i++){bpf_link__destroy(links[i]);}
 ring_buffer__consume(ring);fflush(output);fsync(fileno(output));fclose(output);ring_buffer__free(ring);bpf_object__close(object);return error;
}
