#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "protocol.h"
char LICENSE[] SEC("license")="GPL";
struct {__uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,1024);__type(key,struct sq_key);__type(value,__u32);} watched SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_RINGBUF);__uint(max_entries,1<<24);} events SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__type(key,__u32);__type(value,struct sq_counters);} counters SEC(".maps");

// Operations: 1=open permission, 2=access permission, 3=read completion,
// 4=write completion, 5=rename intent, 6=unlink intent, 7=metadata intent,
// 8=mapping permission. Permission decisions are not completed data I/O.
static __always_inline int capture(struct file *file,struct dentry *entry,
 __u32 operation,__u32 stage,long result,__u32 mask,bool full_paths,struct inode *direct){
 struct inode *inode=direct?direct:file?BPF_CORE_READ(file,f_inode):entry?BPF_CORE_READ(entry,d_inode):0;
 if(!inode)return 0;
 struct sq_key key={.inode=BPF_CORE_READ(inode,i_ino),.device=BPF_CORE_READ(inode,i_sb,s_dev)};
 if(!bpf_map_lookup_elem(&watched,&key))return 0;
 __u32 zero=0;struct sq_counters *count=bpf_map_lookup_elem(&counters,&zero);
 if(!count)return 0;
 __u64 sequence=__sync_fetch_and_add(&count->sequence,1)+1;
 struct sq_event *e=bpf_ringbuf_reserve(&events,sizeof(*e),0);
 if(!e){__sync_fetch_and_add(&count->dropped,1);return 0;}
 // Explicit stores keep LLVM 14 from lowering a large clear to unsupported memset.
 #pragma unroll
 for(int i=0;i<sizeof(*e)/sizeof(__u64);i++)((volatile __u64 *)e)[i]=0;
 e->sequence=sequence;e->observed_ns=bpf_ktime_get_boot_ns();e->operation=operation;e->stage=stage;e->result=result;e->mask=mask;
 e->inode=key.inode;e->device=key.device;e->opener_fsuid=0xffffffff;
 __u64 ids=bpf_get_current_pid_tgid();e->pid=ids>>32;e->tid=(__u32)ids;e->cgroup_id=bpf_get_current_cgroup_id();
 struct task_struct *task=bpf_get_current_task_btf();
 e->process_start_ns=BPF_CORE_READ(task,group_leader,start_boottime);e->ppid=BPF_CORE_READ(task,real_parent,tgid);
 e->uid=BPF_CORE_READ(task,cred,uid.val);e->euid=BPF_CORE_READ(task,cred,euid.val);e->fsuid=BPF_CORE_READ(task,cred,fsuid.val);
 e->loginuid=BPF_CORE_READ(task,loginuid.val);
 if(BPF_CORE_READ(task,flags)&0x00200000)e->flags|=1; // Kernel worker; no implied original user actor.
 bpf_get_current_comm(e->comm,sizeof(e->comm));
 struct mm_struct *mm=task->mm;
 struct file *exe=mm?mm->exe_file:0;
 if(exe){
  e->exe_inode=BPF_CORE_READ(exe,f_inode,i_ino);e->exe_device=BPF_CORE_READ(exe,f_inode,i_sb,s_dev);
  const unsigned char *name=BPF_CORE_READ(exe,f_path.dentry,d_name.name);
  if(bpf_probe_read_kernel_str(e->exe_name,sizeof(e->exe_name),name)<=0)e->flags|=2;
  if(full_paths){if(bpf_d_path(&exe->f_path,e->image,sizeof(e->image))<=0)e->flags|=4;}
  else e->flags|=4; // Full path unavailable at this hook; event-time basename/inode remain authoritative.
 }else e->flags|=2|4;
 struct dentry *dentry=file?BPF_CORE_READ(file,f_path.dentry):entry;
 if(dentry){const unsigned char *name=BPF_CORE_READ(dentry,d_name.name);if(bpf_probe_read_kernel_str(e->file_name,sizeof(e->file_name),name)<=0)e->flags|=8;}else e->flags|=8;
 if(file){e->opener_fsuid=BPF_CORE_READ(file,f_cred,fsuid.val);if(full_paths){if(bpf_d_path(&file->f_path,e->path,sizeof(e->path))<=0)e->flags|=16;}else e->flags|=16;}
 else e->flags|=16;
 bpf_ringbuf_submit(e,0);return 0;
}
SEC("fexit/security_file_open") int BPF_PROG(open_permission,struct file *file,int result){return capture(file,0,1,1,result,0,true,0);}
SEC("fexit/security_file_permission") int BPF_PROG(access_permission,struct file *file,int mask,int result){return capture(file,0,2,1,result,mask,true,0);}
SEC("fexit/vfs_read") int BPF_PROG(read_complete,struct file *file,char *buffer,size_t length,loff_t *position,ssize_t result){return capture(file,0,3,2,result,0,false,0);}
SEC("fexit/vfs_write") int BPF_PROG(write_complete,struct file *file,const char *buffer,size_t length,loff_t *position,ssize_t result){return capture(file,0,4,2,result,0,false,0);}
SEC("fentry/vfs_rename") int BPF_PROG(rename_intent,struct renamedata *data){return capture(0,BPF_CORE_READ(data,old_dentry),5,0,0,0,false,0);}
SEC("fentry/vfs_unlink") int BPF_PROG(unlink_intent,struct user_namespace *ns,struct inode *dir,struct dentry *entry,struct inode **delegated){return capture(0,entry,6,0,0,0,false,0);}
SEC("fentry/notify_change") int BPF_PROG(metadata_intent,struct user_namespace *ns,struct dentry *entry,struct iattr *attributes,struct inode **delegated){return capture(0,entry,7,0,0,BPF_CORE_READ(attributes,ia_valid),false,0);}
SEC("fexit/security_mmap_file") int BPF_PROG(mapping_permission,struct file *file,unsigned long prot,unsigned long flags,int result){return capture(file,0,8,1,result,prot,false,0);}
SEC("fexit/inode_permission") int BPF_PROG(inode_access,struct user_namespace *ns,struct inode *inode,int mask,int result){return capture(0,0,9,1,result,mask,false,inode);}
