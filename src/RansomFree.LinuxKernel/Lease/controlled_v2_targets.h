/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdarg.h>
#include <sys/vfs.h>
#include <linux/magic.h>

struct controlled_target { struct lease_watch_key key; int fd; };

/* Resolve filesystem type through this owned O_PATH descriptor's mount ID.
 * The ext magic alone also covers ext2/ext3 and is not an ext4 assertion.
 * A missing/detached mount, oversized proc record or failed lookup rejects.
 * No original pathname is re-opened or treated as an event-time identity. */
static int controlled_ext4(int fd)
{
 struct statfs fs;char path[64],small[512];unsigned int mount_id=0,found=0;
 if(fstatfs(fd,&fs))return -errno;
 if(fs.f_type!=EXT4_SUPER_MAGIC)return -EXDEV;
 snprintf(path,sizeof(path),"/proc/self/fdinfo/%d",fd);
 FILE *info=fopen(path,"re");if(!info)return -errno;
 while(fgets(small,sizeof(small),info)){
  unsigned int value=0;char suffix=0;
  if(sscanf(small,"mnt_id: %u %c",&value,&suffix)==1){mount_id=value;found++;}
 }
 int failure=ferror(info)?EIO:0;fclose(info);
 if(failure)return -failure;
 if(found!=1||!mount_id)return -EINVAL;
 FILE *mounts=fopen("/proc/self/mountinfo","re");if(!mounts)return -errno;
 char line[65536];size_t bytes=0;int result=-ESTALE;
 while(fgets(line,sizeof(line),mounts)){
  size_t n=strlen(line);bytes+=n;
  if(!n||line[n-1]!='\n'||bytes>16*1024*1024){result=-EOVERFLOW;break;}
  unsigned int current=0;char *end=NULL;
  if(sscanf(line,"%u",&current)!=1||current!=mount_id)continue;
  end=strstr(line," - ");result=end&&!strncmp(end+3,"ext4 ",5)?0:-EXDEV;break;
 }
 if(ferror(mounts))result=-EIO;
 fclose(mounts);return result;
}
static int controlled_target_compare(const void *left,const void *right)
{
 const struct controlled_target *a=left,*b=right;
 if(a->key.device!=b->key.device)return a->key.device>b->key.device?1:-1;
 return a->key.inode==b->key.inode?0:(a->key.inode>b->key.inode?1:-1);
}
static int controlled_pin_targets(struct controlled_target *targets,int count,char **paths)
{
 if(count<1||count>SQ_WATCH_MAX)return -E2BIG;
 for(int n=0;n<count;n++){
  struct stat stat;targets[n].fd=open(paths[n],O_PATH|O_CLOEXEC);
  if(targets[n].fd<0)return -errno;
  if(fstat(targets[n].fd,&stat))return -errno;
  if(!S_ISREG(stat.st_mode)||!stat.st_ino||major(stat.st_dev)>4095||minor(stat.st_dev)>1048575)return -EINVAL;
  int error=controlled_ext4(targets[n].fd);if(error)return error;
  targets[n].key=(struct lease_watch_key){.inode=stat.st_ino,.device=(major(stat.st_dev)<<20)|minor(stat.st_dev),.reserved=0};
  if(!targets[n].key.device)return -EINVAL;
 }
 qsort(targets,(size_t)count,sizeof(*targets),controlled_target_compare);
 for(int n=1;n<count;n++)if(!controlled_target_compare(&targets[n-1],&targets[n]))return -EEXIST;
 return 0;
}
static int controlled_append(char *buffer,size_t *used,const char *format,...)
{
 va_list args;va_start(args,format);
 int length=vsnprintf(buffer+*used,4097-*used,format,args);va_end(args);
 if(length<0)return -EIO;
 if((size_t)length>4096-*used)return -E2BIG;
 *used+=(size_t)length;return 0;
}
static int controlled_ready_v2(char buffer[4097],unsigned int ids[5],struct bpf_map_info infos[5],
 const struct lease_filter *filter,const char *nonce,const struct controlled_target *targets,int count,__u64 lost)
{
 size_t used=0;int error;
#define APPEND(...) do { error=controlled_append(buffer,&used,__VA_ARGS__);if(error)return error; } while(0)
 APPEND("{\"controlledReady\":true,\"controlVersion\":2,\"schemaVersion\":6,\"loadedProgramIds\":[%u,%u,%u,%u,%u],\"attachedProgramIds\":[%u,%u,%u],\"observeAttached\":false,\"denialAttached\":false,\"scratchMapFrozen\":true,\"scratchMapId\":%u,\"configMapFrozen\":true,\"configMapId\":%u,\"eventsMapId\":%u,\"lostMapId\":%u,\"providerEpoch\":%llu,\"activationNonce\":\"%s\",\"targetCount\":%d,\"targets\":[",
  ids[0],ids[1],ids[2],ids[3],ids[4],ids[1],ids[2],ids[3],infos[0].id,infos[1].id,infos[2].id,infos[3].id,filter->epoch,nonce,count);
 for(int n=0;n<count;n++)APPEND("%s{\"ordinal\":%d,\"device\":%u,\"inode\":%llu}",n?",":"",n,targets[n].key.device,targets[n].key.inode);
 APPEND("],\"targetsPinned\":true,\"watchMapId\":%u,\"watchMapFrozen\":true,\"mode\":0,\"lostAtReady\":%llu,\"activationFrame\":\"one-command-then-eof\"}\n",infos[4].id,lost);
#undef APPEND
 return (int)used;
}
