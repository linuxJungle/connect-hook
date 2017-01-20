/*
 * kretprobe_example.c
 *
 * Here's a sample kernel module showing the use of return probes to
 * report the return value and total time taken for probed function
 * to run.
 *
 * usage: insmod kretprobe_example.ko func=<func_name>
 *
 * If no func_name is specified, do_fork is instrumented
 *
 * For more information on theory of operation of kretprobes, see
 * Documentation/kprobes.txt
 *
 * Build and insert the kernel module as done in the kprobe example.
 * You will see the trace data in /var/log/messages and on the console
 * whenever the probed function returns. (Some messages may be suppressed
 * if syslogd is configured to eliminate duplicate messages.)
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <net/inet_sock.h>

/* per-instance private data */
struct my_data {
	int fd;
};

/* Here we use the entry_hanlder to timestamp function entry */
static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct my_data *data;
    data = (struct my_data *)ri->data;
    data->fd = regs->di;
    return 0;
}

static void
long2ip (long ip, char *buf)
{
    sprintf (buf, "%ld.%ld.%ld.%ld", 
                ((0xFF  << 24) & ip) >> 24, 
                ((0xFF << 16) & ip) >> 16,
                ((0xFF << 8) & ip) >> 8, 
                ip & 0xFF);
}
/*
 * Return-probe handler: Log the return value and duration. Duration may turn
 * out to be zero consistently, depending upon the granularity of time
 * accounting on the platform.
 */
static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int retval = regs_return_value(regs);
    int err;
    struct socket *sock;
    struct sock *sk;
    struct my_data *data;
    int fd;
    char   source[16];
    char   dest[16];

    data = (struct my_data *)ri->data;
    fd = data->fd;
    sock = sockfd_lookup(fd, &err);
    if (!sock) {
        printk(KERN_INFO "failed to get socket\n");
        goto out;
    }

    sk = sock->sk;

    if (sk->sk_dport)
        if (!sk->sk_ipv6only) {   /* ipv4 */
            long2ip(htonl(sk->sk_rcv_saddr), source);
            long2ip(htonl(sk->sk_daddr), dest);
            printk(KERN_INFO "sys_connect[%d]: task[%s] pid[%d] fd[%d] family[%d] from source[%s:%d] -> dest[%s:%d]",
                    retval,
                    current->comm,
                    current->pid,
                    fd,
                    sk->sk_family,
                    source,
                    htons(sk->sk_num),
                    dest,
                    htons(sk->sk_dport));
        } else {                 /* ipv6 */
            /*to do*/
        }

out:
    return 0;
}

static struct kretprobe my_kretprobe = {
	.handler		= ret_handler,
	.entry_handler		= entry_handler,
	.data_size		= sizeof(struct my_data),
	/* Probe up to 5 instances concurrently. */
	.maxactive		= 5,
};

static int __init kretprobe_init(void)
{
	int ret;

	my_kretprobe.kp.symbol_name = "sys_connect";
	ret = register_kretprobe(&my_kretprobe);
	if (ret < 0) {
		printk(KERN_INFO "register_kretprobe failed, returned %d\n",
				ret);
		return -1;
	}
	printk(KERN_INFO "Planted return probe at %s: %p\n",
			my_kretprobe.kp.symbol_name, my_kretprobe.kp.addr);
	return 0;
}

static void __exit kretprobe_exit(void)
{
	unregister_kretprobe(&my_kretprobe);
	printk(KERN_INFO "kretprobe at %p unregistered\n",
			my_kretprobe.kp.addr);

	/* nmissed > 0 suggests that maxactive was set too low. */
	printk(KERN_INFO "Missed probing %d instances of %s\n",
		my_kretprobe.nmissed, my_kretprobe.kp.symbol_name);
}

module_init(kretprobe_init)
module_exit(kretprobe_exit)
MODULE_LICENSE("GPL");
