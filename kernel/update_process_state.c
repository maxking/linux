/*
 * On every fork call, update the process state in the hypervisor whenever a new
 * process is created or when process changes its permissions. This way, any
 * malicious process that escalates it's priviledge (maliciously) will cause an
 * inconsistency in states and hypervisor can then take appropriate action.
*/

#include <linux/pid.h>
#include <linux/init.h>
#include <linux/debugfs.h>
#include <linux/dcache.h>
#include <linux/sched.h>

struct dentry *state_toplevel_dir;


/* Just returns the pid in string form to create the debugfs entry. */
static int get_pid_str(long pid, char* pid_str) {
		sprintf(pid_str, "%ld", pid);
		return 0;
}

/*
 * Add a debugfs entry for a new process.
*/
int add_dbfs_proc_entry(struct task_struct *p) {
		char proc_id_str[10];
		struct dentry *proc_dir;

		get_pid_str(p->pid, proc_id_str);

		proc_dir = debugfs_create_dir(proc_id_str, state_toplevel_dir);
		if (proc_dir == NULL){
				printk(KERN_INFO "Error creating debugfs toplevel entry for process %s.", proc_id_str);
		}

		debugfs_create_u32("uid", S_IRUGO , proc_dir, &(p->cred->uid.val));
		debugfs_create_u32("gid", S_IRUGO , proc_dir, &(p->cred->gid.val));

		return 0;
}

/*
 * Get the debugfs entry from the process struct.
 */
struct dentry *get_dbfs_dentry_from_task(struct task_struct *p) {
		char pid_str[10];
		int err = get_pid_str(p->pid, pid_str);
		if (err) {
				printk(KERN_INFO "Unable to find the process pid string for : %s", pid_str);
				return NULL;
		}
		struct qstr qstr = QSTR_INIT(pid_str, strlen(pid_str));
		return d_hash_and_lookup(state_toplevel_dir, &qstr);
}

/*
 * Remove the task entry from the debugfs. First, find the link to dentry and
 * then remove the whole directory iteratively.
 */
int remove_dbfs_proc_entry(struct task_struct *p) {
		struct dentry *dentry = get_dbfs_dentry_from_task(p);
		debugfs_remove_recursive(dentry);
		return 0;
}

void __init initialize(void) {
		state_toplevel_dir = debugfs_create_dir("states", NULL);
		if (state_toplevel_dir == NULL){
				printk(KERN_INFO "Error creating debugfs toplevel entry for process states.");
		}
}

/* Initialize as soon as debugs is initialized.*/
postcore_initcall(initialize);
