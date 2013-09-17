#ifndef _VHOST_H
#define _VHOST_H

#include <linux/eventfd.h>
#include <linux/vhost.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ring.h>
#include <linux/virtio_blk.h>
#include <linux/virtio_net.h>
#include <linux/atomic.h>

struct vhost_device;

struct vhost_work;
typedef void (*vhost_work_fn_t)(struct vhost_work *work);

struct vhost_work {
	struct list_head	  node;
	vhost_work_fn_t		  fn;
	wait_queue_head_t	  done;
	int			  flushing;
	unsigned		  queue_seq;
	unsigned		  done_seq;
	/* a worker might handle work items from different devices thus now we need
	   to know the owner of each work item.
	 */
	struct vhost_virtqueue    *vq;
};

/* Poll a file (eventfd or socket) */
/* Note: there's nothing vhost specific about this structure. */
struct vhost_poll {
	poll_table                table;
	wait_queue_head_t        *wqh;
	wait_queue_t              wait;
	struct vhost_work	  work;
	unsigned long		  mask;
	struct vhost_dev	 *dev;
};

void vhost_work_init(struct vhost_work *work, struct vhost_virtqueue *vq, vhost_work_fn_t fn);
void vhost_work_flush(struct vhost_dev *dev, struct vhost_work *work);
void vhost_work_queue(struct vhost_dev *dev, struct vhost_work *work);

void vhost_poll_init(struct vhost_poll *poll, vhost_work_fn_t fn,
		unsigned long mask, struct vhost_virtqueue  *vq);
int vhost_poll_start(struct vhost_poll *poll, struct file *file);
void vhost_poll_stop(struct vhost_poll *poll);
void vhost_poll_flush(struct vhost_poll *poll);
void vhost_poll_queue(struct vhost_poll *poll);
bool vhost_can_continue(struct vhost_virtqueue  *vq, size_t processed_data, size_t data_min_limit, size_t data_max_limit);

struct vhost_log {
	u64 addr;
	u64 len;
};


struct vhost_ubuf_ref {
	struct kref kref;
	wait_queue_head_t wait;
	struct vhost_virtqueue *vq;
};

struct vhost_ubuf_ref *vhost_ubuf_alloc(struct vhost_virtqueue *, bool zcopy);
void vhost_ubuf_put(struct vhost_ubuf_ref *);
void vhost_ubuf_put_and_wait(struct vhost_ubuf_ref *);
struct stat_entry {
	struct dentry* debugfs_file; /* points to the debugfs file entry */
	void* container; /* point to the memory structure containing the stat value */
	int offset; /* offset in the memory structure where the value is located */
};

struct ubuf_info;

/* The virtqueue structure describes a queue attached to a device. */
struct vhost_virtqueue {
	struct vhost_dev *dev;

	/* The actual ring of buffers. */
	struct mutex mutex;
	unsigned int num;
	struct vring_desc __user *desc;
	struct vring_avail __user *avail;
	struct vring_used __user *used;
	struct file *kick;
	struct file *call;
	struct file *error;
	struct eventfd_ctx *call_ctx;
	struct eventfd_ctx *error_ctx;
	struct eventfd_ctx *log_ctx;

	struct vhost_poll poll;

	/* The routine to call when the Guest pings us, or timeout. */
	vhost_work_fn_t handle_kick;

	/* Last available index we saw. */
	u16 last_avail_idx;

	/* Caches available index value from user. */
	u16 avail_idx;

	/* Last index we used. */
	u16 last_used_idx;

	/* Used flags */
	u16 used_flags;

	/* Last used index value we have signalled on */
	u16 signalled_used;

	/* Last used index value we have signalled on */
	bool signalled_used_valid;

	/* Log writes to used structure. */
	bool log_used;
	u64 log_addr;

	struct iovec iov[UIO_MAXIOV];
	/* hdr is used to store the virtio header.
	 * Since each iovec has >= 1 byte length, we never need more than
	 * header length entries to store the header. */
	struct iovec hdr[sizeof(struct virtio_net_hdr_mrg_rxbuf)];
	struct iovec *indirect;
	size_t vhost_hlen;
	size_t sock_hlen;
	struct vring_used_elem *heads;
	/* We use a kind of RCU to access private pointer.
	 * All readers access it from worker, which makes it possible to
	 * flush the vhost_work instead of synchronize_rcu. Therefore readers do
	 * not need to call rcu_read_lock/rcu_read_unlock: the beginning of
	 * vhost_work execution acts instead of rcu_read_lock() and the end of
	 * vhost_work execution acts instead of rcu_read_unlock().
	 * Writers use virtqueue mutex. */
	void __rcu *private_data;
	/* Log write descriptors */
	void __user *log_base;
	struct vhost_log *log;
	/* vhost zerocopy support fields below: */
	/* last used idx for outstanding DMA zerocopy buffers */
	int upend_idx;
	/* first used idx for DMA done zerocopy buffers */
	int done_idx;
	/* an array of userspace buffers info */
	struct ubuf_info *ubuf_info;
	/* Reference counting for outstanding ubufs.
	 * Protected by vq mutex. Writers must also take device mutex. */
	struct vhost_ubuf_ref *ubufs;
	struct {
		u64 poll_kicks; /* number of kicks in poll mode */
		u64 poll_cycles; /* cycles spent handling kicks in poll mode*/;
		u64 poll_bytes; /* bytes sent/received by kicks in poll mode */
		u64 poll_wait; /* cycles elapsed between poll kicks */
		u64 poll_empty; /* number of times the queue was empty during poll */
		u64 poll_empty_cycles; /* number of cycles elapsed while the queue was empty */
		u64 poll_coalesced; /* number of times this queue was coaelesced */
		u64 poll_limited; /* number of times the queue was limited by netweight during poll kicks*/
		
		u64 notif_works; /* number of worls in notif mode */
		u64 notif_cycles; /* cycles spent handling works in notif mode */
		u64 notif_bytes; /* bytes sent/received by works in notif mode */
		u64 notif_wait; /* cycles elapsed between works in notif mode */
		u64 notif_limited; /* number of times the queue was limited by netweight in notif mode */

		u64 ring_full; /* number of times the ring was full */

		u64 stuck_times; /* how many times this queue was stuck and limited other queues */
		u64 stuck_cycles; /* total amount of cycles the queue was stuck */

		u64 last_poll_tsc_end; /* tsc when the last poll finished */
		u64 last_notif_tsc_end; /* tsc when the last notif finished */
		u64 last_poll_empty_tsc; /* tsc when the queue was detected empty for the first time */
		u64 handled_bytes; /* number of bytes handled by this queue in the last poll/notif. Must beupdated by the concrete vhost implementations (vhost-net)*/
		u64 was_limited; /* flag indicating if the queue was limited by net-weight during the last poll/notif. Must beupdated by the concrete vhost implementations (vhost-net)*/

		struct dentry *debugfs_dir; /* root entry in debugfs for the queue statistics */
		struct stat_entry *entries; /* files created in the queue root entry */
	} stats;
	struct {
		/* When a virtqueue is in vqpoll.enabled mode, it declares
		 * that instead of using guest notifications (kicks) to
		 * discover new work, we prefer to continuously poll this
		 * virtqueue in the worker thread.
		 * If !enabled, the rest of the fields below are undefined.
		 */
		bool enabled;
	 	/* vqpoll.enabled doesn't always mean that this virtqueue is
		 * actually being polled: The backend (e.g., net.c) may
		 * temporarily disable it using vhost_disable/enable_notify().
		 * vqpoll.link is used to maintain the thread's round-robin
		 * list of virtqueus that actually need to be polled.
		 * Note list_empty(link) means this virtqueue isn't polled.
		 */
		struct list_head link;
		/* If this flag is true, the virtqueue is being shut down,
		 * so vqpoll should not be re-enabled.
		 */
		bool shutdown;
		/* Various counters used to decide when to enter polling mode
		 * or leave it and return to notification mode.
		 */
		unsigned long jiffies_last_kick;
		unsigned long jiffies_last_work;
		int work_this_jiffy;
#if 1 /* patcholi vhost-can-continue */
		/* how many items were pending the last time we checked if it was stuck */
		u32 last_pending_items;
		
		/* TSC  when we detected for the first time the queue was stuck
		   Used to measure how many cycles the queue has been stuck
		 */
		u64 stuck_cycles;
#endif
		/* virtqueue.avail is a userspace pointer, and each vhost
		 * device may have a different process context, so polling
		 * different vhost devices could involve page-table switches
		 * (and associated TLB flushes), which hurts performance when
		 * adding nearly-idle guests. So instead, we pin these pages
		 * in memory and keep a kernel-mapped pointer to each, so
		 * polling becomes simple memory reads.
		 */
		struct page *avail_page;
		volatile struct vring_avail *avail_mapped;
	} vqpoll;
};

struct vhost_dev {
	/* Readers use RCU to access memory table pointer
	 * log base pointer and features.
	 * Writers use mutex below.*/
	struct vhost_memory __rcu *memory;
	struct mm_struct *mm;
	struct mutex mutex;
	unsigned acked_features;
	struct vhost_virtqueue *vqs;
	int nvqs;
	struct file *log_file;
	struct eventfd_ctx *log_ctx;
	struct vhost_worker *worker;
	int id;
};
struct vhost_worker {
	spinlock_t work_lock;
	struct list_head work_list;
	struct task_struct *worker_thread;
	
	/* num of devices this worker is currently handling */
	int num_devices;
	/* worker id */
	int id;
	/* linked workers list */
	struct list_head node;
	/* tsc when the last work was processed from the work_list */
	u64 last_work_tsc;
	struct {
		u64 loops; /* number of loops performed */
		u64 enabled_interrupts; /* number of times interrupts were re-enabled */
		u64 cycles; /* cycles spent in the worker, excluding cycles doing queue work */
		u64 switches; /* number of times the mm was  switched */
		u64 wait; /* number of cycles the worker thread was not running after schedule */
		u64 empty_works; /* number of times there were no works in the queue -- ignoring poll kicks  */
		u64 empty_polls; /* number of times there were no queues to poll and the polling queue was not empty  */
		u64 stuck_works; /* number of times were detected stuck and limited queues */
		u64 noqueue_works; /* number of works which have no queue related to them (e.g. vhost-net rx) */
		u64 pending_works; /* number of pending works */;

		u64 last_loop_tsc_end; /* tsc when the last loop was performed */

		struct dentry *debugfs_dir; /* root entry in debugfs for the worker statistics */
		struct stat_entry *entries; /* files created in the queue root entry */
	} stats;
	struct list_head vqpoll_list;
};

struct vhost_workers_pool {
	/* list of active workers */
	struct list_head workers_list;
	/* lock to protect the workers list */
	spinlock_t workers_lock;
	/* last worker id */
	int last_worker_id;
	/* max num of devices a single worker can handle */
	int num_devices_per_worker;	
};


long vhost_dev_init(struct vhost_dev *, struct vhost_virtqueue *vqs, int nvqs);
long vhost_dev_check_owner(struct vhost_dev *);
long vhost_dev_reset_owner(struct vhost_dev *);
void vhost_dev_cleanup(struct vhost_dev *, bool locked);
void vhost_dev_stop(struct vhost_dev *);
long vhost_dev_ioctl(struct vhost_dev *, unsigned int ioctl, void __user *argp);
long vhost_vring_ioctl(struct vhost_dev *d, int ioctl, void __user *argp);
int vhost_vq_access_ok(struct vhost_virtqueue *vq);
int vhost_log_access_ok(struct vhost_dev *);

int vhost_get_vq_desc(struct vhost_dev *, struct vhost_virtqueue *,
		      struct iovec iov[], unsigned int iov_count,
		      unsigned int *out_num, unsigned int *in_num,
		      struct vhost_log *log, unsigned int *log_num);
void vhost_discard_vq_desc(struct vhost_virtqueue *, int n);

int vhost_init_used(struct vhost_virtqueue *);
int vhost_add_used(struct vhost_virtqueue *, unsigned int head, int len);
int vhost_add_used_n(struct vhost_virtqueue *, struct vring_used_elem *heads,
		     unsigned count);
void vhost_add_used_and_signal(struct vhost_dev *, struct vhost_virtqueue *,
			       unsigned int id, int len);
void vhost_add_used_and_signal_n(struct vhost_dev *, struct vhost_virtqueue *,
			       struct vring_used_elem *heads, unsigned count);
void vhost_signal(struct vhost_dev *, struct vhost_virtqueue *);
void vhost_disable_notify(struct vhost_dev *, struct vhost_virtqueue *);
bool vhost_enable_notify(struct vhost_dev *, struct vhost_virtqueue *);

int vhost_log_write(struct vhost_virtqueue *vq, struct vhost_log *log,
		    unsigned int log_num, u64 len);

#define vq_err(vq, fmt, ...) do {                                  \
		pr_debug(pr_fmt(fmt), ##__VA_ARGS__);       \
		if ((vq)->error_ctx)                               \
				eventfd_signal((vq)->error_ctx, 1);\
	} while (0)

enum {
	VHOST_FEATURES = (1ULL << VIRTIO_F_NOTIFY_ON_EMPTY) |
			 (1ULL << VIRTIO_RING_F_INDIRECT_DESC) |
			 (1ULL << VIRTIO_RING_F_EVENT_IDX) |
			 (1ULL << VHOST_F_LOG_ALL),
	VHOST_NET_FEATURES = VHOST_FEATURES |
			 (1ULL << VHOST_NET_F_VIRTIO_NET_HDR) |
			 (1ULL << VIRTIO_NET_F_MRG_RXBUF),
	/* already declare in drivers/vhost/blk.h
	 
	VHOST_BLK_FEATURES =    (1ULL << VIRTIO_F_NOTIFY_ON_EMPTY) |
			(1ULL << VIRTIO_RING_F_INDIRECT_DESC) |
			(1ULL << VIRTIO_BLK_F_SEG_MAX) |
			(1ULL << VIRTIO_BLK_F_GEOMETRY) |
			(1ULL << VIRTIO_BLK_F_TOPOLOGY) |
			(1ULL << VIRTIO_BLK_F_SCSI) |
			(1ULL << VIRTIO_BLK_F_BLK_SIZE),
	*/
};

static inline int vhost_has_feature(struct vhost_dev *dev, int bit)
{
	unsigned acked_features;

	/* TODO: check that we are running from vhost_worker or dev mutex is
	 * held? */
	acked_features = rcu_dereference_index_check(dev->acked_features, 1);
	return acked_features & (1 << bit);
}

void vhost_enable_zcopy(int vq);

#endif
