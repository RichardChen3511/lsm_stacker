#include "stacker.h"
static struct hlist_head stacker_head;
static atomic_t lsm_stacker_ref = ATOMIC_INIT(0);

#define LOCK_STACKER_FOR_READING do { atomic_inc(&lsm_stacker_ref); } while(0)
#define UNLOCK_STACKER_FOR_READING do { atomic_dec(&lsm_stacker_ref); } while(0)

#define RETURN_ERROR_IF_ANY_ERROR(FUNCTION_TO_CALL) do { \
	int final_result = 0; \
	int result; \
	struct hlist_node *pos; \
	struct sec_module *tpos; \
	LOCK_STACKER_FOR_READING; \
	hlist_for_each_entry_rcu(tpos, pos, &stacker_head, hlist) {\
	  struct security_operations *ops = get_mod(tpos);		   \
	  result = ops->FUNCTION_TO_CALL;						   \
	  if (result && !final_result) {						   \
		final_result = result;								   \
		/* if (short_circuit_restrictive) break; */			   \
	  }														   \
	  put_mod(tpos);										   \
	}														   \
	UNLOCK_STACKER_FOR_READING;								   \
	return final_result; } while (0)

#define CALL_ALL(FUNCTION_TO_CALL) do { \
  struct sec_module *tpos;											\
  struct hlist_node *pos;											\
  LOCK_STACKER_FOR_READING;											\
  hlist_for_each_entry_rcu(tpos, pos, &stacker_head, hlist) {		\
    struct security_operations *ops = get_mod(tpos);				\
	ops->FUNCTION_TO_CALL;											\
	put_mod(tpos);                                                  \
  }												                    \
  UNLOCK_STACKER_FOR_READING; } while (0)





int stacker_ptrace (struct task_struct * parent, struct task_struct * child)
{
  RETURN_ERROR_IF_ANY_ERROR(ptrace(parent, child));
}

int stacker_capget (struct task_struct * target,
               kernel_cap_t * effective,
               kernel_cap_t * inheritable, kernel_cap_t * permitted)
{
  RETURN_ERROR_IF_ANY_ERROR(
	capget(target, effective, inheritable, permitted));
}
int stacker_capset_check (struct task_struct * target,
                     kernel_cap_t * effective,
                     kernel_cap_t * inheritable,
						  kernel_cap_t * permitted)
{
  RETURN_ERROR_IF_ANY_ERROR(
	capset_check(target, effective, inheritable, permitted));
}
void stacker_capset_set (struct task_struct * target,
                    kernel_cap_t * effective,
                    kernel_cap_t * inheritable,
                    kernel_cap_t * permitted)
{
  CALL_ALL(
	capset_set(target, effective, inheritable, permitted));
}
int stacker_capable (struct task_struct * tsk, int cap)
{
  RETURN_ERROR_IF_ANY_ERROR(capable(tsk, cap));
}
int stacker_acct (struct file * file)
{
  RETURN_ERROR_IF_ANY_ERROR(acct(file));
}
int stacker_sysctl (struct ctl_table * table, int op)
{
  RETURN_ERROR_IF_ANY_ERROR(sysctl(table, op));
}

int stacker_quotactl (int cmds, int type, int id, struct super_block * sb)
{
  RETURN_ERROR_IF_ANY_ERROR(quotactl(cmds, type, id, sb));
}
int stacker_quota_on (struct dentry * dentry)
{
  RETURN_ERROR_IF_ANY_ERROR(quota_on(dentry));
}
int stacker_syslog (int type)
{
  RETURN_ERROR_IF_ANY_ERROR(syslog(type));
}
int stacker_settime (struct timespec *ts, struct timezone *tz)
{
  RETURN_ERROR_IF_ANY_ERROR(settime(ts, tz));
}
int stacker_vm_enough_memory (long pages)
{
  RETURN_ERROR_IF_ANY_ERROR(vm_enough_memory(pages));
}

int stacker_bprm_alloc_security (struct linux_binprm * bprm)
{
  RETURN_ERROR_IF_ANY_ERROR(bprm_alloc_security(bprm));
}

void stacker_bprm_free_security (struct linux_binprm * bprm)
{
  CALL_ALL(bprm_free_security(bprm));
}
void stacker_bprm_apply_creds (struct linux_binprm * bprm, int unsafe)
{
  CALL_ALL(bprm_apply_creds(bprm, unsafe));
}
void stacker_bprm_post_apply_creds (struct linux_binprm * bprm)
{
  CALL_ALL(bprm_post_apply_creds(bprm));
}

int stacker_bprm_set_security (struct linux_binprm * bprm)
{
  RETURN_ERROR_IF_ANY_ERROR(bprm_set_security(bprm));
}
int stacker_bprm_check_security (struct linux_binprm * bprm)
{
  RETURN_ERROR_IF_ANY_ERROR(bprm_check_security(bprm));
}
int stacker_bprm_secureexec (struct linux_binprm * bprm)
{
  RETURN_ERROR_IF_ANY_ERROR(bprm_secureexec(bprm));
}

int stacker_sb_alloc_security (struct super_block * sb)
{
    RETURN_ERROR_IF_ANY_ERROR(sb_alloc_security(sb));
}

void stacker_sb_free_security (struct super_block * sb)
{
    CALL_ALL(sb_free_security(sb));
}

int stacker_sb_copy_data (struct file_system_type *type,
                    void *orig, void *copy)
{
    RETURN_ERROR_IF_ANY_ERROR(sb_copy_data(type, orig, copy));
}
int stacker_sb_kern_mount (struct super_block *sb, void *data)
{
    RETURN_ERROR_IF_ANY_ERROR(sb_kern_mount(sb, data));
}
int stacker_sb_statfs (struct dentry *dentry)
{
    RETURN_ERROR_IF_ANY_ERROR(sb_statfs(dentry));

}
int stacker_sb_mount (char *dev_name, struct nameidata * nd,
                 char *type, unsigned long flags, void *data)
{
    RETURN_ERROR_IF_ANY_ERROR(sb_mount(dev_name, nd, type, flags, data));
}

int stacker_sb_check_sb (struct vfsmount * mnt, struct nameidata * nd)
{
    RETURN_ERROR_IF_ANY_ERROR(sb_check_sb(mnt, nd));
}

int stacker_sb_umount (struct vfsmount * mnt, int flags)
{
    RETURN_ERROR_IF_ANY_ERROR(sb_umount(mnt, flags));
}
void stacker_sb_umount_close (struct vfsmount * mnt)
{
    CALL_ALL(sb_umount_close(mnt));
}
void stacker_sb_umount_busy (struct vfsmount * mnt)
{
    CALL_ALL(sb_umount_close(mnt));
}
void stacker_sb_post_remount (struct vfsmount * mnt,
                         unsigned long flags, void *data)
{
    CALL_ALL(sb_post_remount(mnt, flags, data));
}
void stacker_sb_post_mountroot (void)
{
    CALL_ALL(sb_post_mountroot());
}
void stacker_sb_post_addmount (struct vfsmount * mnt,
                          struct nameidata * mountpoint_nd)
{
    CALL_ALL(sb_post_addmount(mnt, mountpoint_nd));
}

int stacker_sb_pivotroot (struct nameidata * old_nd,
                     struct nameidata * new_nd)
{
    RETURN_ERROR_IF_ANY_ERROR(sb_pivotroot(old_nd, new_nd));
}
void stacker_sb_post_pivotroot (struct nameidata * old_nd,
                           struct nameidata * new_nd)
{
    CALL_ALL(sb_post_pivotroot(old_nd, new_nd));
}

int stacker_inode_alloc_security (struct inode *inode)
{
    RETURN_ERROR_IF_ANY_ERROR(inode_alloc_security(inode));
}
void stacker_inode_free_security (struct inode *inode)
{
    CALL_ALL(inode_free_security(inode));
}

int stacker_inode_init_security (struct inode *inode, struct inode *dir,
                            char **name, void **value, size_t *len)
{
    RETURN_ERROR_IF_ANY_ERROR(
            inode_init_security(inode, dir, name, value, len));
}
int stacker_inode_create (struct inode *dir,
                     struct dentry *dentry, int mode)
{
    RETURN_ERROR_IF_ANY_ERROR(inode_create(dir, dentry, mode));
}
int stacker_inode_link (struct dentry *old_dentry,
                   struct inode *dir, struct dentry *new_dentry)
{
    RETURN_ERROR_IF_ANY_ERROR(inode_link(old_dentry, dir, new_dentry));
}

int stacker_inode_unlink (struct inode *dir, struct dentry *dentry)
{
    RETURN_ERROR_IF_ANY_ERROR(inode_unlink(dir, dentry));
}
int stacker_inode_symlink (struct inode *dir,
                      struct dentry *dentry, const char *old_name)
{
    RETURN_ERROR_IF_ANY_ERROR(inode_symlink(dir, dentry, old_name));
}
int stacker_inode_mkdir (struct inode *dir, struct dentry *dentry, int mode)
{
    RETURN_ERROR_IF_ANY_ERROR(inode_mkdir(dir, dentry, mode));
}
int stacker_inode_rmdir (struct inode *dir, struct dentry *dentry)
{
    RETURN_ERROR_IF_ANY_ERROR(inode_rmdir(dir, dentry));
}
int stacker_inode_mknod (struct inode *dir, struct dentry *dentry,
                    int mode, dev_t dev)
{
    RETURN_ERROR_IF_ANY_ERROR(inode_mknod(dir, dentry, mode, dev));
}
int stacker_inode_rename (struct inode *old_dir, struct dentry *old_dentry,
                     struct inode *new_dir, struct dentry *new_dentry)
{
    RETURN_ERROR_IF_ANY_ERROR(inode_rename(old_dir, old_dentry, new_dir, new_dentry));
}
int stacker_inode_readlink (struct dentry *dentry)
{
    RETURN_ERROR_IF_ANY_ERROR(inode_readlink(dentry));
}
int stacker_inode_follow_link (struct dentry *dentry, struct nameidata *nd)
{
    RETURN_ERROR_IF_ANY_ERROR(inode_follow_link(dentry, nd));
}
int stacker_inode_permission (struct inode *inode, int mask, struct nameidata *nd)
{
    RETURN_ERROR_IF_ANY_ERROR(inode_permission(inode, mask, nd));
}
int stacker_inode_setattr (struct dentry *dentry, struct iattr *attr)
{
    RETURN_ERROR_IF_ANY_ERROR(inode_setattr(dentry, attr));
}
int stacker_inode_getattr (struct vfsmount *mnt, struct dentry *dentry)
{
    RETURN_ERROR_IF_ANY_ERROR(inode_getattr(mnt, dentry));
}
void stacker_inode_delete (struct inode *inode)
{
    CALL_ALL(inode_delete(inode));
}
int stacker_inode_setxattr (struct dentry *dentry, char *name, void *value,
                       size_t size, int flags)
{
    RETURN_ERROR_IF_ANY_ERROR(inode_setxattr(dentry, name, value, size, flags));
}
void stacker_inode_post_setxattr (struct dentry *dentry, char *name, void *value,
                             size_t size, int flags)
{
    CALL_ALL(inode_post_setxattr(dentry, name, value, size, flags));
}
int stacker_inode_getxattr (struct dentry *dentry, char *name)
{
    RETURN_ERROR_IF_ANY_ERROR(inode_getxattr(dentry, name));
}
int stacker_inode_listxattr (struct dentry *dentry)
{
    RETURN_ERROR_IF_ANY_ERROR(inode_listxattr(dentry));
}
int stacker_inode_removexattr (struct dentry *dentry, char *name)
{
    RETURN_ERROR_IF_ANY_ERROR(inode_removexattr(dentry, name));
}
const char *(*inode_xattr_getsuffix) (void);
int stacker_inode_getsecurity(const struct inode *inode, const char *name, void *buffer, size_t size, int err)
{
    RETURN_ERROR_IF_ANY_ERROR(
            inode_getsecurity(inode, name, buffer, size, err));
}
int stacker_inode_setsecurity(struct inode *inode, const char *name, const void *value, size_t size, int flags)
{
    RETURN_ERROR_IF_ANY_ERROR(
            inode_setsecurity(inode, name, value, size, flags));
}
int stacker_inode_listsecurity(struct inode *inode, char *buffer, size_t buffer_size)
{
    RETURN_ERROR_IF_ANY_ERROR(
            inode_listsecurity(inode, buffer, buffer_size));
}

int stacker_file_permission (struct file * file, int mask)
{
    RETURN_ERROR_IF_ANY_ERROR(
            file_permission(file, mask));
}
int stacker_file_alloc_security (struct file * file)
{
    RETURN_ERROR_IF_ANY_ERROR(
            file_alloc_security(file));
}
void stacker_file_free_security (struct file * file)
{
    CALL_ALL(file_free_security(file));
}
int stacker_file_ioctl (struct file * file, unsigned int cmd,
                   unsigned long arg)
{
    RETURN_ERROR_IF_ANY_ERROR(
            file_ioctl(file, cmd, arg));
}
int stacker_file_mmap (struct file * file,
                  unsigned long reqprot,
                  unsigned long prot, unsigned long flags)
{
    RETURN_ERROR_IF_ANY_ERROR(
            file_mmap(file, reqprot, prot, flags));
}
int stacker_file_mprotect (struct vm_area_struct * vma,
                      unsigned long reqprot,
                      unsigned long prot)
{
    RETURN_ERROR_IF_ANY_ERROR(
            file_mprotect(vma, reqprot, prot));
}
int stacker_file_lock (struct file * file, unsigned int cmd)
{
    RETURN_ERROR_IF_ANY_ERROR(file_lock(file, cmd));
}
int stacker_file_fcntl (struct file * file, unsigned int cmd,
                   unsigned long arg)
{
    RETURN_ERROR_IF_ANY_ERROR(file_fcntl(file, cmd, arg));
}
int stacker_file_set_fowner (struct file * file)
{
    RETURN_ERROR_IF_ANY_ERROR(file_set_fowner(file));
}
int stacker_file_send_sigiotask (struct task_struct * tsk,
                            struct fown_struct * fown, int sig)
{
    RETURN_ERROR_IF_ANY_ERROR(file_send_sigiotask(tsk, fown, sig));
}
int stacker_file_receive (struct file * file)
{
    RETURN_ERROR_IF_ANY_ERROR(file_receive(file));
}

int stacker_task_create (unsigned long clone_flags)
{
    RETURN_ERROR_IF_ANY_ERROR(task_create(clone_flags));
}
int stacker_task_alloc_security (struct task_struct * p)
{
    RETURN_ERROR_IF_ANY_ERROR(task_alloc_security(p));
}
void stacker_task_free_security (struct task_struct * p)
{
    CALL_ALL(task_free_security(p));
}
int stacker_task_setuid (uid_t id0, uid_t id1, uid_t id2, int flags)
{
    RETURN_ERROR_IF_ANY_ERROR(task_setuid(id0, id1, id2, flags));
}
int stacker_task_post_setuid (uid_t old_ruid /* or fsuid */ ,
                         uid_t old_euid, uid_t old_suid, int flags)
{
    RETURN_ERROR_IF_ANY_ERROR(task_post_setuid(old_ruid, old_euid, old_suid, flags));
}
int stacker_task_setgid (gid_t id0, gid_t id1, gid_t id2, int flags)
{
    RETURN_ERROR_IF_ANY_ERROR(task_setgid(id0, id1, id2, flags));
}
int stacker_task_setpgid (struct task_struct * p, pid_t pgid)
{
    RETURN_ERROR_IF_ANY_ERROR(task_setpgid(p, pgid));
}
int stacker_task_getpgid (struct task_struct * p)
{
    RETURN_ERROR_IF_ANY_ERROR(task_getpgid(p));
}
int stacker_task_getsid (struct task_struct * p)
{
    RETURN_ERROR_IF_ANY_ERROR(task_getsid(p));
}
void stacker_task_getsecid (struct task_struct * p, u32 * secid)
{
    CALL_ALL(task_getsecid(p, secid));
}
int stacker_task_setgroups (struct group_info *group_info)
{
    RETURN_ERROR_IF_ANY_ERROR(task_setgroups(group_info));
}
int stacker_task_setnice (struct task_struct * p, int nice)
{
    RETURN_ERROR_IF_ANY_ERROR(task_setnice(p, nice));
}
int stacker_task_setioprio (struct task_struct * p, int ioprio)
{
    RETURN_ERROR_IF_ANY_ERROR(task_setioprio(p, ioprio));
}
int stacker_task_getioprio (struct task_struct * p)
{
    RETURN_ERROR_IF_ANY_ERROR(task_getioprio(p));
}
int stacker_task_setrlimit (unsigned int resource, struct rlimit * new_rlim)
{
    RETURN_ERROR_IF_ANY_ERROR(task_setrlimit(resource, new_rlim));
}
int stacker_task_setscheduler (struct task_struct * p, int policy,
                          struct sched_param * lp)
{
    RETURN_ERROR_IF_ANY_ERROR(task_setscheduler(p, policy, lp));
}
int stacker_task_getscheduler (struct task_struct * p)
{
    RETURN_ERROR_IF_ANY_ERROR(task_getscheduler(p));
}
int stacker_task_movememory (struct task_struct * p)
{
    RETURN_ERROR_IF_ANY_ERROR(task_movememory(p));
}
int stacker_task_kill (struct task_struct * p,
                  struct siginfo * info, int sig, u32 secid)
{
    RETURN_ERROR_IF_ANY_ERROR(task_kill(p, info, sig, secid));
}
int stacker_task_wait (struct task_struct * p)
{
    RETURN_ERROR_IF_ANY_ERROR(task_wait(p));
}
int stacker_task_prctl (int option, unsigned long arg2,
                   unsigned long arg3, unsigned long arg4,
                   unsigned long arg5)
{
    RETURN_ERROR_IF_ANY_ERROR(task_prctl(option,arg2, arg3, arg4, arg5));
}
void stacker_task_reparent_to_init (struct task_struct * p)
{
    CALL_ALL(task_reparent_to_init(p));
}
void stacker_task_to_inode(struct task_struct *p, struct inode *inode)
{
    CALL_ALL(task_to_inode(p, inode));
}

int stacker_ipc_permission (struct kern_ipc_perm * ipcp, short flag)
{
    RETURN_ERROR_IF_ANY_ERROR(ipc_permission(ipcp, flag));
}

int stacker_msg_msg_alloc_security (struct msg_msg * msg)
{
    RETURN_ERROR_IF_ANY_ERROR(msg_msg_alloc_security(msg));
}
void stacker_msg_msg_free_security (struct msg_msg * msg)
{
    CALL_ALL(msg_msg_free_security(msg));
}

int stacker_msg_queue_alloc_security (struct msg_queue * msq)
{
    RETURN_ERROR_IF_ANY_ERROR(msg_queue_alloc_security(msq));
}
void stacker_msg_queue_free_security (struct msg_queue * msq)
{
    CALL_ALL(msg_queue_free_security(msq));
}
int stacker_msg_queue_associate (struct msg_queue * msq, int msqflg)
{
    RETURN_ERROR_IF_ANY_ERROR(msg_queue_associate(msq, msqflg));
}
int stacker_msg_queue_msgctl (struct msg_queue * msq, int cmd)
{
    RETURN_ERROR_IF_ANY_ERROR(msg_queue_msgctl(msq, cmd));
}
int stacker_msg_queue_msgsnd (struct msg_queue * msq,
                         struct msg_msg * msg, int msqflg)
{
    RETURN_ERROR_IF_ANY_ERROR(msg_queue_msgsnd(msq, msg, msqflg));
}
int stacker_msg_queue_msgrcv (struct msg_queue * msq,
                         struct msg_msg * msg,
                         struct task_struct * target,
                         long type, int mode)
{
    RETURN_ERROR_IF_ANY_ERROR(
                msg_queue_msgrcv(msq, msg, target, type, mode));
}

int stacker_shm_alloc_security (struct shmid_kernel * shp)
{
    RETURN_ERROR_IF_ANY_ERROR(shm_alloc_security(shp));
}
void stacker_shm_free_security (struct shmid_kernel * shp)
{
    CALL_ALL(shm_free_security(shp));
}
int stacker_shm_associate (struct shmid_kernel * shp, int shmflg)
{
    RETURN_ERROR_IF_ANY_ERROR(shm_associate(shp, shmflg));
}
int stacker_shm_shmctl (struct shmid_kernel * shp, int cmd)
{
    RETURN_ERROR_IF_ANY_ERROR(shm_shmctl(shp, cmd));
}
int stacker_shm_shmat (struct shmid_kernel * shp,
                  char __user *shmaddr, int shmflg)
{
    RETURN_ERROR_IF_ANY_ERROR(shm_shmat(shp, shmaddr, shmflg));
}

int stacker_sem_alloc_security (struct sem_array * sma)
{
    RETURN_ERROR_IF_ANY_ERROR(sem_alloc_security(sma));
}
void stacker_sem_free_security (struct sem_array * sma)
{
    CALL_ALL(sem_free_security(sma));
}
int stacker_sem_associate (struct sem_array * sma, int semflg)
{
    RETURN_ERROR_IF_ANY_ERROR(sem_associate(sma, semflg));
}
int stacker_sem_semctl (struct sem_array * sma, int cmd)
{
    RETURN_ERROR_IF_ANY_ERROR(sem_semctl(sma, cmd));
}
int stacker_sem_semop (struct sem_array * sma,
                  struct sembuf * sops, unsigned nsops, int alter)
{
    RETURN_ERROR_IF_ANY_ERROR(sem_semop(sma, sops, nsops, alter));
}

int stacker_netlink_send (struct sock * sk, struct sk_buff * skb)
{
    RETURN_ERROR_IF_ANY_ERROR(netlink_send(sk, skb));
}
int stacker_netlink_recv (struct sk_buff * skb, int cap)
{
    RETURN_ERROR_IF_ANY_ERROR(netlink_recv(skb, cap));
}

/* allow module stacking */
int stacker_register_security (const char *name,
                          struct security_operations *ops)
{
    RETURN_ERROR_IF_ANY_ERROR(register_security(name, ops));
}
int stacker_unregister_security (const char *name,
                            struct security_operations *ops)
{
    RETURN_ERROR_IF_ANY_ERROR(unregister_security(name, ops));
}

void stacker_d_instantiate (struct dentry *dentry, struct inode *inode)
{
    CALL_ALL(d_instantiate(dentry, inode));
}

int stacker_getprocattr(struct task_struct *p, char *name, void *value, size_t size)
{
    RETURN_ERROR_IF_ANY_ERROR(getprocattr(p, name, value, size));
}
int stacker_setprocattr(struct task_struct *p, char *name, void *value, size_t size)
{
    RETURN_ERROR_IF_ANY_ERROR(setprocattr(p, name, value, size));
}
int stacker_secid_to_secctx(u32 secid, char **secdata, u32 *seclen)
{
    RETURN_ERROR_IF_ANY_ERROR(secid_to_secctx(secid, secdata, seclen));
}
void stacker_release_secctx(char *secdata, u32 seclen)
{
    CALL_ALL(release_secctx(secdata, seclen));
}

#ifdef CONFIG_SECURITY_NETWORK
int stacker_unix_stream_connect (struct socket * sock,
                            struct socket * other, struct sock * newsk)
{
    RETURN_ERROR_IF_ANY_ERROR(unix_stream_connect(sock, other, newsk));
}
int stacker_unix_may_send (struct socket * sock, struct socket * other)
{
    RETURN_ERROR_IF_ANY_ERROR(unix_may_send(sock, other));
}

int stacker_socket_create (int family, int type, int protocol, int kern)
{
    RETURN_ERROR_IF_ANY_ERROR(socket_create(family, type, protocol, kern));
}
void stacker_socket_post_create (struct socket * sock, int family,
                            int type, int protocol, int kern)
{
    CALL_ALL(socket_post_create(sock, family, type, protocol, kern));
}
int stacker_socket_bind (struct socket * sock,
                    struct sockaddr * address, int addrlen)
{
    RETURN_ERROR_IF_ANY_ERROR(socket_bind(sock, address, addrlen));
}
int stacker_socket_connect (struct socket * sock,
                       struct sockaddr * address, int addrlen)
{
    RETURN_ERROR_IF_ANY_ERROR(socket_connect(sock, address, addrlen));
}
int stacker_socket_listen (struct socket * sock, int backlog)
{
    RETURN_ERROR_IF_ANY_ERROR(socket_listen(sock, backlog));
}
int stacker_socket_accept (struct socket * sock, struct socket * newsock)
{
    RETURN_ERROR_IF_ANY_ERROR(socket_accept(sock, newsock));
}
void stacker_socket_post_accept (struct socket * sock,
                            struct socket * newsock)
{
    CALL_ALL(socket_post_accept(sock, newsock));
}
int stacker_socket_sendmsg (struct socket * sock,
                       struct msghdr * msg, int size)
{
    RETURN_ERROR_IF_ANY_ERROR(socket_sendmsg(sock, msg, size));
}
int stacker_socket_recvmsg (struct socket * sock,
                       struct msghdr * msg, int size, int flags)
{
    RETURN_ERROR_IF_ANY_ERROR(socket_recvmsg(sock, msg, size, flags));
}
int stacker_socket_getsockname (struct socket * sock)
{
    RETURN_ERROR_IF_ANY_ERROR(socket_getsockname(sock));
}
int stacker_socket_getpeername (struct socket * sock)
{
    RETURN_ERROR_IF_ANY_ERROR(socket_getpeername(sock));
}
int stacker_socket_getsockopt (struct socket * sock, int level, int optname)
{
    RETURN_ERROR_IF_ANY_ERROR(socket_getsockopt(sock, level, optname));
}
int stacker_socket_setsockopt (struct socket * sock, int level, int optname)
{
    RETURN_ERROR_IF_ANY_ERROR(socket_setsockopt(sock, level, optname));
}
int stacker_socket_shutdown (struct socket * sock, int how)
{
    RETURN_ERROR_IF_ANY_ERROR(socket_shutdown(sock, how));
}
int stacker_socket_sock_rcv_skb (struct sock * sk, struct sk_buff * skb)
{
    RETURN_ERROR_IF_ANY_ERROR(socket_sock_rcv_skb(sk, skb));
}
int stacker_socket_getpeersec_stream (struct socket *sock, char __user *optval, int __user *optlen, unsigned len)
{
    RETURN_ERROR_IF_ANY_ERROR(socket_getpeersec_stream(sock, optval, optlen, len));
}
int stacker_socket_getpeersec_dgram (struct socket *sock, struct sk_buff *skb, u32 *secid)
{
    RETURN_ERROR_IF_ANY_ERROR(socket_getpeersec_dgram(sock, skb, secid));
}
int stacker_sk_alloc_security (struct sock *sk, int family, gfp_t priority)
{
    RETURN_ERROR_IF_ANY_ERROR(sk_alloc_security(sk, family, priority));
}
void stacker_sk_free_security (struct sock *sk)
{
    CALL_ALL(sk_free_security(sk));
}
unsigned int stacker_sk_getsid (struct sock *sk, struct flowi *fl, u8 dir)
{
    RETURN_ERROR_IF_ANY_ERROR(sk_getsid(sk, fl, dir));
}
#endif /* CONFIG_SECURITY_NETWORK */

#ifdef CONFIG_SECURITY_NETWORK_XFRM
int stacker_xfrm_policy_alloc_security (struct xfrm_policy *xp, struct xfrm_user_sec_ctx *sec_ctx)
{
    RETURN_ERROR_IF_ANY_ERROR(xfrm_policy_alloc_security(xp, sec_ctx));
}
int stacker_xfrm_policy_clone_security (struct xfrm_policy *old, struct xfrm_policy *new)
{
    RETURN_ERROR_IF_ANY_ERROR(xfrm_policy_clone_security(old, new));
}
void stacker_xfrm_policy_free_security (struct xfrm_policy *xp)
{
    CALL_ALL(xfrm_policy_free_security(xp));
}
int stacker_xfrm_policy_delete_security (struct xfrm_policy *xp)
{
    RETURN_ERROR_IF_ANY_ERROR(xfrm_policy_delete_security(xp));
}
int stacker_xfrm_state_alloc_security (struct xfrm_state *x, struct xfrm_user_sec_ctx *sec_ctx, u32 secid)
{
    RETURN_ERROR_IF_ANY_ERROR(xfrm_state_alloc_security(x, sec_ctx, secid));
}
void stacker_xfrm_state_free_security (struct xfrm_state *x)
{
    CALL_ALL(xfrm_state_free_security(x));
}
int stacker_xfrm_state_delete_security (struct xfrm_state *x)
{
    RETURN_ERROR_IF_ANY_ERROR(xfrm_state_delete_security(x));
}
int stacker_xfrm_policy_lookup(struct xfrm_policy *xp, u32 sk_sid, u8 dir){
{
    RETURN_ERROR_IF_ANY_ERROR(xfrm_policy_lookup(xp, sk_sid, dir));
}
#endif /* CONFIG_SECURITY_NETWORK_XFRM */

/* key management security hooks */
#ifdef CONFIG_KEYS
int stacker_key_alloc(struct key *key, struct task_struct *tsk, unsigned long flags)
{
    RETURN_ERROR_IF_ANY_ERROR(key_alloc(key, tsk, flags));
}

void stacker_key_free(struct key *key)
{
    CALL_ALL(key_free(key));
}
int stacker_key_permission(key_ref_t key_ref,
                      struct task_struct *context,
                      key_perm_t perm)
{
    RETURN_ERROR_IF_ANY_ERROR(key_permission(key_ref, context, perm));
}

#endif  /* CONFIG_KEYS */


static struct security_operations lsm_stacker_ops = {
    .ptrace = stacker_ptrace,
    .capget = stacker_capget,

    .capset_check = stacker_capset_check,
    .capset_set = stacker_capset_set,
    .capable = stacker_capable,
    .acct = stacker_acct,
    .sysctl = stacker_sysctl,
    .quotactl = stacker_quotactl,
    .quota_on = stacker_quota_on,
    .syslog = stacker_syslog,
    .settime = stacker_settime,
    .vm_enough_memory = stacker_vm_enough_memory,

    .bprm_alloc_security = stacker_bprm_alloc_security,
    .bprm_free_security = stacker_bprm_free_security,
    .bprm_apply_creds = stacker_bprm_apply_creds,
    .bprm_post_apply_creds = stacker_bprm_post_apply_creds,
    .bprm_set_security = stacker_bprm_set_security,
    .bprm_check_security = stacker_bprm_check_security,
    .bprm_secureexec = stacker_bprm_secureexec,

    .sb_alloc_security = stacker_sb_alloc_security,
    .sb_free_security = stacker_sb_free_security,
    .sb_copy_data = stacker_sb_copy_data,
    .sb_kern_mount = stacker_sb_kern_mount,
    .sb_statfs = stacker_sb_statfs,
    .sb_mount = stacker_sb_mount,
    .sb_check_sb = stacker_sb_check_sb,
    .sb_umount = stacker_sb_umount,
    .sb_umount_close = stacker_sb_umount_close,
    .sb_umount_busy = stacker_sb_umount_busy,
    .sb_post_remount = stacker_sb_post_remount,
    .sb_post_mountroot = stacker_sb_post_mountroot,
    .sb_post_addmount = stacker_sb_post_addmount,
    .sb_pivotroot = stacker_sb_pivotroot,

    .inode_alloc_security = stacker_inode_alloc_security,
    .inode_free_security = stacker_inode_free_security,
    .inode_init_security = stacker_inode_init_security,
    .inode_create = stacker_inode_create,
    .inode_link = stacker_inode_link,
    .inode_unlink = stacker_inode_unlink,
    .inode_symlink = stacker_inode_symlink,
    .inode_mkdir = stacker_inode_mkdir,
    .inode_rmdir = stacker_inode_rmdir,
    .inode_mknod = stacker_inode_mknod,
    .inode_rename = stacker_inode_rename,
    .inode_readlink = stacker_inode_readlink,
    .inode_follow_link = stacker_inode_follow_link,
    .inode_permission = stacker_inode_permission,
    .inode_setattr = stacker_inode_setattr,
    .inode_getattr = stacker_inode_getattr,
    .inode_delete = stacker_inode_delete,
    .inode_setxattr = stacker_inode_setxattr,
    .inode_post_setxattr = stacker_inode_post_setxattr,
    .inode_getxattr = stacker_inode_getxattr,
    .inode_listxattr = stacker_inode_listxattr,
    .inode_removexattr = stacker_inode_removexattr,
    .inode_getsecurity = stacker_inode_getsecurity,
    .inode_setsecurity = stacker_inode_setsecurity,
    .inode_listsecurity = stacker_inode_listsecurity,

    .file_permission = stacker_file_permission,
    .file_alloc_security = stacker_file_alloc_security,
    .file_free_security = stacker_file_free_security,
    .file_ioctl = stacker_file_ioctl,
    .file_mmap = stacker_file_mmap,
    .file_mprotect = stacker_file_mprotect,
    .file_lock = stacker_file_lock,
    .file_fcntl = stacker_file_fcntl,
    .file_set_fowner = stacker_file_set_fowner,
    .file_send_sigiotask = stacker_file_send_sigiotask,
    .file_receive = stacker_file_receive,

    .task_create = stacker_task_create,
    .task_alloc_security = stacker_task_alloc_security,
    .task_free_security = stacker_task_free_security,
    .task_setuid = stacker_task_setuid,
    .task_post_setuid = stacker_task_post_setuid,
    .task_setgid = stacker_task_setgid,
    .task_setpgid = stacker_task_setpgid,
    .task_getpgid = stacker_task_getpgid,
    .task_getsid = stacker_task_getsid,
    .task_getsecid = stacker_task_getsecid,
    .task_setgroups = stacker_task_setgroups,
    .task_setnice = stacker_task_setnice,
    .task_setioprio = stacker_task_setioprio,
    .task_getioprio = stacker_task_getioprio,
    .task_setrlimit = stacker_task_setrlimit,
    .task_setscheduler = stacker_task_setscheduler,
    .task_getscheduler = stacker_task_getscheduler,
    .task_movememory = stacker_task_movememory,
    .task_kill = stacker_task_kill,
    .task_wait = stacker_task_wait,
    .task_prctl = stacker_task_prctl,
    .task_reparent_to_init = stacker_task_reparent_to_init,
    .task_to_inode = stacker_task_to_inode,

    .ipc_permission = stacker_ipc_permission,

    .msg_msg_alloc_security = stacker_msg_msg_alloc_security,
    .msg_msg_free_security = stacker_msg_msg_free_security,

    .msg_queue_alloc_security = stacker_msg_queue_alloc_security,
    .msg_queue_free_security = stacker_msg_queue_free_security,
    .msg_queue_associate = stacker_msg_queue_associate,
    .msg_queue_msgctl = stacker_msg_queue_msgctl,
    .msg_queue_msgsnd = stacker_msg_queue_msgsnd,
    .msg_queue_msgrcv = stacker_msg_queue_msgrcv,

    .shm_alloc_security = stacker_shm_alloc_security,
    .shm_free_security = stacker_shm_free_security,
    .shm_associate = stacker_shm_associate,
    .shm_shmctl = stacker_shm_shmctl,
    .shm_shmat = stacker_shm_shmat,
    .sem_alloc_security = stacker_sem_alloc_security,
    .sem_free_security = stacker_sem_free_security,
    .sem_associate = stacker_sem_associate,
    .sem_semctl = stacker_sem_semctl,
    .sem_semop = stacker_sem_semop,

    .netlink_send = stacker_netlink_send,
    .netlink_recv = stacker_netlink_recv,

    /* allow module stacking */
    .register_security = stacker_register_security,
    .unregister_security = stacker_unregister_security,

    .d_instantiate = stacker_d_instantiate,

    .getprocattr = stacker_getprocattr,
    .setprocattr = stacker_setprocattr,
    .secid_to_secctx = stacker_secid_to_secctx,
    .release_secctx = stacker_release_secctx,

#ifdef CONFIG_SECURITY_NETWORK
    .unix_stream_connect = stacker_unix_stream_connect,
    .unix_may_send = stacker_unix_may_send,

    .socket_create = stacker_socket_create,
    .socket_post_create = stacker_socket_post_create,
    .socket_bind = stacker_socket_bind,
    .socket_connect = stacker_socket_connect,
    .socket_listen = stacker_socket_listen,
    .socket_accept = stacker_socket_accept,
    .socket_post_accept = stacker_socket_post_accept,
    .socket_sendmsg = stacker_socket_sendmsg,
    .socket_recvmsg = stacker_socket_recvmsg,
    .socket_getsockname = stacker_socket_getsockname,
    .socket_getpeername = stacker_socket_getpeername,
    .socket_getsockopt = stacker_socket_getsockopt,
    .socket_setsockopt = stacker_socket_setsockopt,
    .socket_shutdown = stacker_socket_shutdown,
    .socket_sock_rcv_skb = stacker_socket_sock_rcv_skb,
    .socket_getpeersec_stream = stacker_socket_getpeersec_stream,
    .socket_getpeersec_dgram = stacker_socket_getpeersec_dgram,
    .sk_alloc_security = stacker_sk_alloc_security,
    .sk_free_security = stacker_sk_free_security,
#endif   /* CONFIG_SECURITY_NETWORK */

#ifdef CONFIG_SECURITY_NETWORK_XFRM
    .xfrm_policy_alloc_security = stacker_xfrm_policy_alloc_security,
    .xfrm_policy_clone_security = stacker_xfrm_policy_clone_security,
    .xfrm_policy_free_security = stacker_xfrm_policy_free_security,
    .xfrm_policy_delete_security = stacker_xfrm_policy_delete_security,
    .xfrm_state_alloc_security = stacker_xfrm_state_alloc_security,
    .xfrm_state_free_security = stacker_xfrm_state_free_security,
    .xfrm_state_delete_security = stacker_xfrm_state_delete_security,
    .xfrm_policy_lookup = stacker_xfrm_policy_lookup,
#endif  /* CONFIG_SECURITY_NETWORK_XFRM */

    /* key management security hooks */
#ifdef CONFIG_KEYS
    .key_alloc = stacker_key_alloc,
    .key_free = stacker_key_free,
    .key_permission = stacker_key_permission

#endif  /* CONFIG_KEYS */

};



	
static char *module_name = "lsm_stacker";
static int __init lsm_stacker_init (void)
{
	int res;
	struct sec_module *old_modules;
	strcut secrity_operations **orignal_ops;

	INIT_HLIST_HEAD(&stacker_head);

	if (!security_reigster(&lsm_stacker_ops)) 
		goto has_reg;
	printk(KERN_INFO "has security module register");

	if (!security_mod_register(module_name, &lsm_stacker_ops)) 
		goto has_reg;
	printk(KERN_INFO "current security module is not support"
					"nultiple security modules");

	orignal_ops = (struct security_operations **) __symbol_get("security_ops");

	if (!orgnal_ops) {
		res = -1; 
		printk(KERN_ERR "get security_ops symbol fail\n");
		goto out;
	}

	old_modules = kmalloc(sizeof(*old_modules), GFP_KERNEL);
	if (!old_modules) {
		res = -ENOMEM;
		goto out;
	}

	old_modules->ops = *orignal_ops;
	old_modules->modname = "orignal_sec_modules";
	INIT_HLIST_NODE(&old_modules->hlist);
	hlist_add_tail(&old_modules->hlist, &stacker_head);

	smp_wmb();
	*orignal_ops = &lsm_stacker_ops;
	smb_wmb();

has_reg:
	printk(KERN_INFO "LSM STACKER MODULES REGISTER SUCCESS\n");

out:
	return res;
}


static void __exit lsm_stacker_exit (void)
{
	return;
}


module_init (lsm_stacker_init);
module_exit (lsm_stacker_exit);

MODULE_DESCRIPTION("LSM Stacker - supports multiple simultaneous LSM modules");
MODULE_AUTHOR("Richard Chen");
MODULE_LICENSE("GPL v2");
