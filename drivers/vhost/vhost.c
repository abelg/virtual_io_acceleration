/* Copyright (C) 2009 Red Hat, Inc.
 * Copyright (C) 2006 Rusty Russell IBM Corporation
 * Copyright (C) IBM Corporation, 2013
 *
 * Author: Michael S. Tsirkin <mst@redhat.com>
 *
 * Inspiration, some code, and most witty comments come from
 * Documentation/virtual/lguest/lguest.c, by Rusty Russell
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
 * Generic code for virtio server in host kernel.
 */

#include <linux/eventfd.h>
#include <linux/vhost.h>
#include <linux/virtio_net.h>
#include <linux/mm.h>
#include <linux/mmu_context.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/cgroup.h>
#include <linux/jiffies.h>

#include "vhost.h"

#include <linux/moduleparam.h>
static int devices_per_worker = 7;
module_param(devices_per_worker, int, S_IRUGO);
MODULE_PARM_DESC(devices_per_worker, "Setup the number of devices used by a single vhost worker thread");


static int poll_coalescing = 0; 
module_param(poll_coalescing, int, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(poll_coalescing, "Batch notifications made in less than this many jiffiess. Must be higher than poll_stop_idle.");

static int poll_start_rate = 1;
module_param(poll_start_rate, int, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(poll_start_rate, "Start continuous polling of virtqueue when rate of events is at least this number per jiffy. If 0, never start polling.");

static int poll_stop_idle = 3*HZ; /* 3 seconds */
module_param(poll_stop_idle, int, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(poll_stop_idle, "Stop continuous polling of virtqueue after this many jiffies of no work.");

/* not yet supported */
static int poll_stop_rate = 0;
module_param(poll_stop_rate, int, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(poll_stop_rate, "Stop continuous polling of virtqueue if rate of events drops below this number per seconds (at least for a jiffie).");

/* not yet supported */
static int max_work_stuck_cycles = -1;
module_param(max_work_stuck_cycles, int, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(max_work_stuck_cycles, "How many cycles need to elapse to consider the worker list stuck (-1 = disabled)");

static int max_queue_stuck_cycles = -1;
module_param(max_queue_stuck_cycles, int, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(max_queue_stuck_cycles, "How many cycles need to elapse to consider a queue as a stuck queue (-1 = disabled)");

static int max_queue_stuck_size = 0;
module_param(max_queue_stuck_size, int, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(max_queue_stuck_size, "The queue will be considered stuck as long as there are no more than this number of items (0=disabled)");
enum {
	VHOST_MEMORY_MAX_NREGIONS = 64,
	VHOST_MEMORY_F_LOG = 0x1,
};

static unsigned vhost_zcopy_mask __read_mostly;
static struct vhost_workers_pool workers_pool;

#define vhost_used_event(vq) ((u16 __user *)&vq->avail->ring[vq->num])
#define vhost_avail_event(vq) ((u16 __user *)&vq->used->ring[vq->num])

static void vhost_poll_func(struct file *file, wait_queue_head_t *wqh,
			    poll_table *pt)
{
	struct vhost_poll *poll;

	poll = container_of(pt, struct vhost_poll, table);
	poll->wqh = wqh;
	add_wait_queue(wqh, &poll->wait);
}

static int vhost_poll_wakeup(wait_queue_t *wait, unsigned mode, int sync,
			     void *key)
{
	struct vhost_poll *poll = container_of(wait, struct vhost_poll, wait);

	if (!((unsigned long)key & poll->mask))
		return 0;

	vhost_poll_queue(poll);
	return 0;
}

void vhost_work_init(struct vhost_work *work, struct vhost_virtqueue *vq, vhost_work_fn_t fn)
{
	INIT_LIST_HEAD(&work->node);
	work->fn = fn;
	init_waitqueue_head(&work->done);
	work->flushing = 0;
	work->queue_seq = work->done_seq = 0;
	work->vq = vq;
}

/* Init poll structure */
void vhost_poll_init(struct vhost_poll *poll, vhost_work_fn_t fn,
		     unsigned long mask, struct vhost_virtqueue *vq)
{
	init_waitqueue_func_entry(&poll->wait, vhost_poll_wakeup);
	init_poll_funcptr(&poll->table, vhost_poll_func);
	poll->mask = mask;
	poll->dev = vq->dev;

	vhost_work_init(&poll->work, vq, fn);
}

/* Start polling a file. We add ourselves to file's wait queue. The caller must
 * keep a reference to a file until after vhost_poll_stop is called. */
int vhost_poll_start(struct vhost_poll *poll, struct file *file)
{
	unsigned long mask;
	int ret = 0;

	mask = file->f_op->poll(file, &poll->table);
	if (mask)
		vhost_poll_wakeup(&poll->wait, 0, 0, (void *)mask);
	if (mask & POLLERR) {
		if (poll->wqh)
			remove_wait_queue(poll->wqh, &poll->wait);
		ret = -EINVAL;
	}

	return ret;
}

/* Stop polling a file. After this function returns, it becomes safe to drop the
 * file reference. You must also flush afterwards. */
void vhost_poll_stop(struct vhost_poll *poll)
{
	if (poll->wqh) {
		remove_wait_queue(poll->wqh, &poll->wait);
		poll->wqh = NULL;
	}
}

static bool vhost_work_seq_done(struct vhost_dev *dev, struct vhost_work *work,
				unsigned seq)
{
	int left;

	spin_lock_irq(&dev->worker->work_lock);
	left = seq - work->done_seq;
	spin_unlock_irq(&dev->worker->work_lock);
	return left <= 0;
}

static void vhost_work_flush(struct vhost_dev *dev, struct vhost_work *work)
{
	unsigned seq;
	int flushing;

	spin_lock_irq(&dev->worker->work_lock);
	seq = work->queue_seq;
	work->flushing++;
	spin_unlock_irq(&dev->worker->work_lock);
	wait_event(work->done, vhost_work_seq_done(dev, work, seq));
	spin_lock_irq(&dev->worker->work_lock);
	flushing = --work->flushing;
	spin_unlock_irq(&dev->worker->work_lock);       
	BUG_ON(flushing < 0);
}

/* Flush any work that has been scheduled. When calling this, don't hold any
 * locks that are also used by the callback. */
void vhost_poll_flush(struct vhost_poll *poll)
{
	vhost_work_flush(poll->dev, &poll->work);
}

void vhost_work_queue(struct vhost_dev *dev, struct vhost_work *work)
{
	unsigned long flags;

	spin_lock_irqsave(&dev->worker->work_lock, flags);
	if (list_empty(&work->node)) {
		list_add_tail(&work->node, &dev->worker->work_list);
		work->queue_seq++;
		wake_up_process(dev->worker->worker_thread);
	}
	spin_unlock_irqrestore(&dev->worker->work_lock, flags); 
}

void vhost_poll_queue(struct vhost_poll *poll)
{
	vhost_work_queue(poll->dev, &poll->work);
}

/* Enable or disable virtqueue polling (vqpoll.enabled) for a virtqueue.
 *
 * Enabling this mode it tells the guest not to notify ("kick") us when its
 * has made more work available on this virtqueue; Rather, we will hontinuously
 * poll this virtqueue in the worker thread. If multiple virtqueues are polled,
 * the worker thread polls them all, e.g., in a round-robin fashion.
 * Note that vqpoll.enabled doesn't always mean that this virtqueue is
 * actually being polled: The backend (e.g., net.c) may temporarily disable it
 * using vhost_disable/enable_notify(), while vqpoll.enabled is unchanged.
 *
 * It is assumed that these functions are called relatively rarely, when vhost
 * notices that this virtqueue's usage pattern significantly changed in a way
 * that makes polling more efficient than notification, or vice versa.
 * Also, we assume that vhost_vq_disable_vqpoll() is always called on vq
 * cleanup, so any allocations done by vhost_vq_enable_vqpoll() can be
 * reclaimed.
 */
static void vhost_vq_enable_vqpoll(struct vhost_virtqueue *vq)
{
	if (vq->vqpoll.enabled)
		return; /* already enabled, nothing to do */
	if (!vq->handle_kick)
		return; /* polling will be a waste of time if no callback! */
	if (!(vq->used_flags & VRING_USED_F_NO_NOTIFY)) {
		/* vq has guest notifications enabled. Disable them,
		   and instead add vq to the polling list */
		vhost_disable_notify(vq->dev, vq);
		list_add_tail(&vq->vqpoll.link, &vq->dev->worker->vqpoll_list);
	}
	vq->vqpoll.jiffies_last_kick = jiffies;
	__get_user(vq->avail_idx, &vq->avail->idx); // TODO: do we need to do this? also,  if we do, why not just use the mapped below?

	vq->vqpoll.enabled = true;

	/* Map userspace's vq->avail to the kernel's memory space, so it
	 * can be polled without slow switching of page tables. This is
	 * important so that inactive guests still on the polling list
	 * do not slow down an active guest.
	 */
	if (get_user_pages_fast((unsigned long)vq->avail, 1, 0,
		&vq->vqpoll.avail_page) != 1) {
		// TODO: I think this can't happen because we check access
		// to vq->avail in advance, right??
		BUG();
	}
	vq->vqpoll.avail_mapped = (struct vring_avail *) (
		(unsigned long)kmap(vq->vqpoll.avail_page) |
		((unsigned long)vq->avail & ~PAGE_MASK));
}

/*
 * This function doesn't always succeed in changing the mode. Sometimes
 * a temporary race condition prevents turning on guest notifications, so
 * vq should be polled next time again.
 */
static void vhost_vq_disable_vqpoll(struct vhost_virtqueue *vq)
{
	if (!vq->vqpoll.enabled) {
		return; /* already disabled, nothing to do */
	}
	vq->vqpoll.enabled = false;

	if (!list_empty(&vq->vqpoll.link)) {
		/* vq is on the polling list, remove it from this list and
		 * instead enable guest notifications. */
		list_del_init(&vq->vqpoll.link);
		if (unlikely(vhost_enable_notify(vq->dev,vq))
			&& !vq->vqpoll.shutdown) {
			/* Race condition: guest wrote before we enabled
			 * notification, so we'll never get a notification for
			 * this work - so continue polling mode for a while. */
			vhost_disable_notify(vq->dev, vq);
			vq->vqpoll.enabled = true;
			vhost_enable_notify(vq->dev, vq);
			return;
		}
	}

	if (vq->vqpoll.avail_mapped) {
		kunmap(vq->vqpoll.avail_page);
		put_page(vq->vqpoll.avail_page);
		vq->vqpoll.avail_mapped = 0;
	}
}

static void vhost_vq_reset(struct vhost_dev *dev,
			   struct vhost_virtqueue *vq)
{
	vq->num = 1;
	vq->desc = NULL;
	vq->avail = NULL;
	vq->used = NULL;
	vq->last_avail_idx = 0;
	vq->avail_idx = 0;
	vq->last_used_idx = 0;
	vq->signalled_used = 0;
	vq->signalled_used_valid = false;
	vq->used_flags = 0;
	vq->log_used = false;
	vq->log_addr = -1ull;
	vq->vhost_hlen = 0;
	vq->sock_hlen = 0;
	vq->private_data = NULL;
	vq->log_base = NULL;
	vq->error_ctx = NULL;
	vq->error = NULL;
	vq->kick = NULL;
	vq->call_ctx = NULL;
	vq->call = NULL;
	vq->log_ctx = NULL;
	vq->upend_idx = 0;
	vq->done_idx = 0;
	vq->ubufs = NULL;
	INIT_LIST_HEAD(&vq->vqpoll.link);
	vq->vqpoll.enabled = false;
	vq->vqpoll.shutdown = false;
	vq->vqpoll.avail_mapped = NULL;
}

/* Switch the current kernel thread's mm context (page tables) to the given
 * one, if necessary (if it's not already using this mm context).
 */
static inline void set_mm(struct vhost_virtqueue *vq) {
	struct mm_struct *mm = vq->dev->mm;
	if (current->mm != mm)
		use_mm(mm);
}

/* roundrobin_poll() takes worker->vqpoll_list, and returns one of the
 * virtqueues which the caller should kick, or NULL in case none should be
 * kicked. roundrobin_poll() also disables polling on a virtqueue which has
 * been polled for too long without success.
 *
 * This current implementation (the "round-robin" implementation) only
 * polls the first vq in the list, returning it or NULL as appropriate, and
 * moves this vq to the end of the list, so next time a different one is
 * polled.
 */
static struct vhost_virtqueue *roundrobin_poll(struct list_head *list) {
	struct vhost_virtqueue *vq;
	u16 avail_idx;

	if (list_empty(list))
		return NULL;

	vq = list_first_entry(list, struct vhost_virtqueue, vqpoll.link);
	WARN_ON(!vq->vqpoll.enabled);
	list_move_tail(&vq->vqpoll.link, list);

	/* If poll_coalescing is set, avoid kicking the same vq too often */
	if (jiffies - vq->vqpoll.jiffies_last_kick < poll_coalescing)
		return NULL;

	/* See if there is any new work available from the guest. */
	/* TODO: need to check the optional idx feature, and if we haven't
	 * reached that idx yet, don't kick... */
	avail_idx = vq->vqpoll.avail_mapped->idx;
	if (avail_idx != vq->last_avail_idx) {
		return vq;
	}
	if (jiffies > vq->vqpoll.jiffies_last_kick + poll_stop_idle) {
		/* We've been polling this virtqueue for a long time with no
		 * results, so switch back to guest notification
		 */
		set_mm(vq);
		vhost_vq_disable_vqpoll(vq);
	}
	return NULL;    
}


/*
 * Check if any of the queues has pending works and no new items has been
 * added for specific amount of time. This probably means that the queue is stuck
 * and the pending items need to be processed ASAP to release it so the VM can continue
 * processing data. If no stuck queues were found, continue as far as the amount of data
 * processed is less than the specified limit.
 */
bool vhost_can_continue(struct vhost_virtqueue  *vq, size_t processed_data, size_t data_min_limit, size_t data_max_limit) {
	struct vhost_virtqueue *vq_iterator, *next = NULL;
	struct list_head *list = &vq->dev->worker->vqpoll_list;
	u64 elapsed_cycles;
	u64 cycles;


	// if we didn't process the minimum amount of data we can always continue
	if (processed_data < data_min_limit)
		return true;

	// If we processed moren than the maximum we can not continue
	if (processed_data > data_max_limit)
		return false;

	rdtscll(cycles);
	elapsed_cycles = cycles - vq->dev->worker->last_work_tsc;
	// if there are work items pending for too long we can not continue
	if (max_work_stuck_cycles>=0 && elapsed_cycles>max_work_stuck_cycles && !list_empty(&vq->dev->worker->work_list)) {
		return false;
	}

	// check if there are stuck queues 
	if (max_queue_stuck_cycles >=0) {
		list_for_each_entry_safe(vq_iterator, next, list, vqpoll.link) {                        
			u16 pending_items;                      

			// ignore the queue that is currently being processed
			if (vq_iterator == vq) {
				vq_iterator->vqpoll.last_pending_items = 0;
				continue;
			}

			// ignore queues that has no pending data
			pending_items = vq_iterator->vqpoll.avail_mapped->idx - vq_iterator->last_avail_idx;
			if (pending_items == 0) {
				vq_iterator->vqpoll.last_pending_items = 0;
				continue;
			}

			rdtscll(cycles);
			// check if the queue stuck with pending data since the last check (?)
			if (pending_items == vq_iterator->vqpoll.last_pending_items) {
				// stuck sizes is used to avoid detecting a bursty queue as a stuck queue
				// (don't consider a queue stuck if it holds too many items = max_queue_stuck_size)
				if (max_queue_stuck_size >  0 &&  pending_items > max_queue_stuck_size)
					continue;

				elapsed_cycles = cycles - vq_iterator->vqpoll.stuck_cycles;                           
				// is the queue stuck for too long ?
				if (elapsed_cycles >= max_queue_stuck_cycles) {

					// put current queue in the 2nd place if it didn't send more than half of the max
					// and it's being polled
					if (vq->vqpoll.enabled && processed_data < data_max_limit / 2)
						list_move(&vq->vqpoll.link, list);

					// put stuck queue in the 1st place if it's being polled
					list_move(&vq_iterator->vqpoll.link, list);
					return false;
				}
			} else {
				// the queue is not stuck, reset stuck 
				vq_iterator->vqpoll.last_pending_items = pending_items;
				vq_iterator->vqpoll.stuck_cycles = cycles;
			}
		}
	}

	// no stuck queues, no works, no maximum  => we can continue
	return true;
}
static int vhost_worker_thread(void *data)
{
	struct vhost_worker *worker = data;
	struct vhost_work *work = NULL;
	unsigned uninitialized_var(seq);
	mm_segment_t oldfs = get_fs();

	set_fs(USER_DS);

	for (;;) {
		/* mb paired w/ kthread_stop */
		set_current_state(TASK_INTERRUPTIBLE);

		spin_lock_irq(&worker->work_lock);
		if (work) {
			work->done_seq = seq;
			if (work->flushing)
				wake_up_all(&work->done);
		}               

		if (kthread_should_stop()) {
			spin_unlock_irq(&worker->work_lock);
			__set_current_state(TASK_RUNNING);
			break;
		}
		if (!list_empty(&worker->work_list)) {
			work = list_first_entry(&worker->work_list,
					struct vhost_work, node);
			list_del_init(&work->node);
			seq = work->queue_seq;
		} else
			work = NULL;
		spin_unlock_irq(&worker->work_lock);

		if (work) {
			struct vhost_virtqueue *vq = work->vq;
			__set_current_state(TASK_RUNNING);
			if (kthread_should_stop()) {
				spin_unlock_irq(&worker->work_lock);
				break;
			}
			if (vq)
				set_mm(vq);
			work->fn(work);
			rdtscll(worker->last_work_tsc);
			/* Keep track of the work rate, for deciding when to
			 * enable polling */
			if (vq) {
				if (vq->vqpoll.jiffies_last_work != jiffies) {
					vq->vqpoll.jiffies_last_work = jiffies;
					vq->vqpoll.work_this_jiffy = 0;
				}
				vq->vqpoll.work_this_jiffy++;
			}
			/* If vq is in the round-robin list of virtqueues being
			 * constantly checked by this thread, move vq the end
			 * of the queue, because it had its fair chance now.
			 */
			if (vq && !list_empty(&vq->vqpoll.link)) {
				list_move_tail(&vq->vqpoll.link,
					&worker->vqpoll_list);
			}
			/* Otherwise, if this vq is looking for notifications
			 * but vq polling is not enabled for it, do it now.
			 */
			else if (poll_start_rate && vq && vq->handle_kick &&
				!vq->vqpoll.enabled &&
				!vq->vqpoll.shutdown &&
				!(vq->used_flags & VRING_USED_F_NO_NOTIFY) &&
				vq->vqpoll.work_this_jiffy >=
					poll_start_rate) {
				vhost_vq_enable_vqpoll(vq);
			}
		}

		/* Check one virtqueue from the round-robin list */
		if (!list_empty(&worker->vqpoll_list)) {
			struct vhost_virtqueue *vq;
			vq = roundrobin_poll(&worker->vqpoll_list);
			if (vq) {
				set_mm(vq);
				vq->handle_kick(&vq->poll.work);
				vq->vqpoll.jiffies_last_kick=jiffies;
			}
			/* If our polling list isn't empty, ask to continue
			 * running this thread, don't yield.
			 */
			__set_current_state(TASK_RUNNING);
		}
		if (need_resched())
			schedule();
	}
	set_fs(oldfs);
	return 0;
}

static void vhost_vq_free_iovecs(struct vhost_virtqueue *vq)
{
	kfree(vq->indirect);
	vq->indirect = NULL;
	kfree(vq->log);
	vq->log = NULL;
	kfree(vq->heads);
	vq->heads = NULL;
	kfree(vq->ubuf_info);
	vq->ubuf_info = NULL;
}

void vhost_enable_zcopy(int vq)
{
	vhost_zcopy_mask |= 0x1 << vq;
}

void vhost_init(void)
{
	workers_pool.num_devices_per_worker = devices_per_worker;
	spin_lock_init(&workers_pool.workers_lock);
	INIT_LIST_HEAD(&workers_pool.workers_list);
}

void vhost_exit(void)
{
}


/* Helper to allocate iovec buffers for all vqs. */
static long vhost_dev_alloc_iovecs(struct vhost_dev *dev)
{
	int i;
	bool zcopy;

	for (i = 0; i < dev->nvqs; ++i) {
		dev->vqs[i].indirect = kmalloc(sizeof *dev->vqs[i].indirect *
					       UIO_MAXIOV, GFP_KERNEL);
		dev->vqs[i].log = kmalloc(sizeof *dev->vqs[i].log * UIO_MAXIOV,
					  GFP_KERNEL);
		dev->vqs[i].heads = kmalloc(sizeof *dev->vqs[i].heads *
					    UIO_MAXIOV, GFP_KERNEL);
		zcopy = vhost_zcopy_mask & (0x1 << i);
		if (zcopy)
			dev->vqs[i].ubuf_info =
				kmalloc(sizeof *dev->vqs[i].ubuf_info *
					UIO_MAXIOV, GFP_KERNEL);
		if (!dev->vqs[i].indirect || !dev->vqs[i].log ||
			!dev->vqs[i].heads ||
			(zcopy && !dev->vqs[i].ubuf_info))
			goto err_nomem;
	}
	return 0;

err_nomem:
	for (; i >= 0; --i)
		vhost_vq_free_iovecs(&dev->vqs[i]);
	return -ENOMEM;
}

static void vhost_dev_free_iovecs(struct vhost_dev *dev)
{
	int i;

	for (i = 0; i < dev->nvqs; ++i)
		vhost_vq_free_iovecs(&dev->vqs[i]);
}
/* assign a worker for the device */
static void vhost_dev_assign_worker(struct vhost_dev *dev)
{	
	struct vhost_worker *worker;
	bool create_new_worker = true;

	spin_lock_irq(&workers_pool.workers_lock);
	list_for_each_entry(worker, &workers_pool.workers_list, node) {
		if (worker->num_devices < workers_pool.num_devices_per_worker) {
			create_new_worker = false;
			break;
		}
	}

	if (create_new_worker) {
		worker = kmalloc(sizeof *worker, GFP_KERNEL);
		worker->id = ++workers_pool.last_worker_id;
		worker->num_devices = 0;
		spin_lock_init(&worker->work_lock);
		INIT_LIST_HEAD(&worker->work_list);		
		list_add(&worker->node, &workers_pool.workers_list);
		worker->worker_thread = kthread_create(vhost_worker_thread,
						worker, "vhost-%d", worker->id);
		/*
		 * vqpoll_list starts out empty, so we don't continuously
		 * poll on any virtqueue, and rather just wait for guest
		 * notifications. Later when we notice work on some virtqueue,
		 * we will switch it to polling mode, i.e., add it to
		 * vqpoll_list and disable guest notifications.
		 */
		INIT_LIST_HEAD(&worker->vqpoll_list);

	}
	spin_unlock_irq(&workers_pool.workers_lock);

	worker->num_devices++;
	dev->worker    = worker;
}

long vhost_dev_init(struct vhost_dev *dev,
		    struct vhost_virtqueue *vqs, int nvqs)
{
	int i;

	dev->vqs = vqs;
	dev->nvqs = nvqs;
	mutex_init(&dev->mutex);
	dev->log_ctx = NULL;
	dev->log_file = NULL;
	dev->memory = NULL;
	dev->mm = NULL;
	vhost_dev_assign_worker(dev);

	for (i = 0; i < dev->nvqs; ++i) {
		dev->vqs[i].log = NULL;
		dev->vqs[i].indirect = NULL;
		dev->vqs[i].heads = NULL;
		dev->vqs[i].ubuf_info = NULL;
		dev->vqs[i].dev = dev;
		mutex_init(&dev->vqs[i].mutex);
		vhost_vq_reset(dev, dev->vqs + i);
		if (dev->vqs[i].handle_kick)
			vhost_poll_init(&dev->vqs[i].poll,
					dev->vqs[i].handle_kick, POLLIN, &dev->vqs[i]);
	}

	return 0;
}

/* Caller should have device mutex */
long vhost_dev_check_owner(struct vhost_dev *dev)
{
	/* Are you the owner? If not, I don't think you mean to do that */
	return dev->mm == current->mm ? 0 : -EPERM;
}

struct vhost_attach_cgroups_struct {
	struct vhost_work work;
	struct task_struct *owner;
	int ret;
};

static void vhost_attach_cgroups_work(struct vhost_work *work)
{
	struct vhost_attach_cgroups_struct *s;

	s = container_of(work, struct vhost_attach_cgroups_struct, work);
	s->ret = cgroup_attach_task_all(s->owner, current);
}

static int vhost_attach_cgroups(struct vhost_dev *dev)
{
	struct vhost_attach_cgroups_struct attach;

	attach.owner = current;
	vhost_work_init(&attach.work, NULL, vhost_attach_cgroups_work);
	vhost_work_queue(dev, &attach.work);
	vhost_work_flush(dev, &attach.work);
	return attach.ret;
}

/* Caller should have device mutex */
static long vhost_dev_set_owner(struct vhost_dev *dev)
{
	struct task_struct *worker;
	int err;

	/* Is there an owner already? */
	if (dev->mm) {
		err = -EBUSY;
		goto err_mm;
	}

	/* No owner, become one */
	dev->mm = get_task_mm(current);
	wake_up_process(dev->worker->worker_thread);  /* avoid contributing to loadavg */

	err = vhost_attach_cgroups(dev);
	if (err)
		goto err_cgroup;

	err = vhost_dev_alloc_iovecs(dev);
	if (err)
		goto err_cgroup;

	return 0;
err_cgroup:
	kthread_stop(worker);
	dev->worker = NULL;
err_mm:
	return err;
}

/* Caller should have device mutex */
long vhost_dev_reset_owner(struct vhost_dev *dev)
{
	struct vhost_memory *memory;

	/* Restore memory to default empty mapping. */
	memory = kmalloc(offsetof(struct vhost_memory, regions), GFP_KERNEL);
	if (!memory)
		return -ENOMEM;

	vhost_dev_cleanup(dev, true);

	memory->nregions = 0;
	RCU_INIT_POINTER(dev->memory, memory);
	return 0;
}

void vhost_dev_stop(struct vhost_dev *dev)
{
	int i;

	for (i = 0; i < dev->nvqs; ++i) {
		if (dev->vqs[i].kick && dev->vqs[i].handle_kick) {
			vhost_poll_stop(&dev->vqs[i].poll);
			vhost_poll_flush(&dev->vqs[i].poll);
		}
	}
}

/* shutdown_vqpoll() asks the worker thread to shut down virtqueue polling
 * mode for a given virtqueue which is itself being shut down. We ask the
 * worker thread to do this rather than doing it directly, so that we don't
 * race with the worker thread's use of the queue.
 */
static void shutdown_vqpoll_work(struct vhost_work *work)
{
	work->vq->vqpoll.shutdown = true;
	vhost_vq_disable_vqpoll(work->vq);
	WARN_ON(work->vq->vqpoll.avail_mapped);
}

static void shutdown_vqpoll(struct vhost_virtqueue *vq)
{
	struct vhost_work work;
	vhost_work_init(&work, vq, shutdown_vqpoll_work);
	vhost_work_queue(vq->dev, &work);
	vhost_work_flush(vq->dev, &work);
}

/* Caller should have device mutex if and only if locked is set */
void vhost_dev_cleanup(struct vhost_dev *dev, bool locked)
{
	int i;

	for (i = 0; i < dev->nvqs; ++i) {
		if (dev->vqs[i].error_ctx)
			eventfd_ctx_put(dev->vqs[i].error_ctx);
		if (dev->vqs[i].error)
			fput(dev->vqs[i].error);
		if (dev->vqs[i].kick)
			fput(dev->vqs[i].kick);
		if (dev->vqs[i].call_ctx)
			eventfd_ctx_put(dev->vqs[i].call_ctx);
		if (dev->vqs[i].call)
			fput(dev->vqs[i].call);

		shutdown_vqpoll(&dev->vqs[i]);
		// TODO: Think: When a device goes down, the worker might
		// still have its mm as its current mm. We will never use it
		// again (before the next work, we switch mm again) but maybe
		// holding it wastes memory?
		vhost_vq_reset(dev, dev->vqs + i);
	}
	vhost_dev_free_iovecs(dev);
	if (dev->log_ctx)
		eventfd_ctx_put(dev->log_ctx);
	dev->log_ctx = NULL;
	if (dev->log_file)
		fput(dev->log_file);
	dev->log_file = NULL;
	/* No one will access memory at this point */
	kfree(rcu_dereference_protected(dev->memory,
					locked ==
						lockdep_is_held(&dev->mutex)));
	RCU_INIT_POINTER(dev->memory, NULL);
	if (dev->worker) {
		spin_lock_irq(&workers_pool.workers_lock);
		// decrease number of devices
		if (dev->worker->num_devices)
			--dev->worker->num_devices;
		// release worker if no devices are being handled
		if ( dev->worker->num_devices == 0) {
			if (dev->worker->worker_thread) {
				kthread_stop(dev->worker->worker_thread);
				dev->worker->worker_thread = NULL;
				list_del(&dev->worker->node);
			}
		}
		spin_unlock_irq(&workers_pool.workers_lock);
		// avoid the following, the device might still use worker lock
		// dev->worker = NULL;
	}
	// TODO: maybe we need to copy dev->mm, zero it, and only then mmput,
	// to ensure we don't mm_use it again?
	if (dev->mm)
		mmput(dev->mm);
	dev->mm = NULL;
}

static int log_access_ok(void __user *log_base, u64 addr, unsigned long sz)
{
	u64 a = addr / VHOST_PAGE_SIZE / 8;

	/* Make sure 64 bit math will not overflow. */
	if (a > ULONG_MAX - (unsigned long)log_base ||
	    a + (unsigned long)log_base > ULONG_MAX)
		return 0;

	return access_ok(VERIFY_WRITE, log_base + a,
			 (sz + VHOST_PAGE_SIZE * 8 - 1) / VHOST_PAGE_SIZE / 8);
}

/* Caller should have vq mutex and device mutex. */
static int vq_memory_access_ok(void __user *log_base, struct vhost_memory *mem,
			       int log_all)
{
	int i;

	if (!mem)
		return 0;

	for (i = 0; i < mem->nregions; ++i) {
		struct vhost_memory_region *m = mem->regions + i;
		unsigned long a = m->userspace_addr;
		if (m->memory_size > ULONG_MAX)
			return 0;
		else if (!access_ok(VERIFY_WRITE, (void __user *)a,
				    m->memory_size))
			return 0;
		else if (log_all && !log_access_ok(log_base,
						   m->guest_phys_addr,
						   m->memory_size))
			return 0;
	}
	return 1;
}

/* Can we switch to this memory table? */
/* Caller should have device mutex but not vq mutex */
static int memory_access_ok(struct vhost_dev *d, struct vhost_memory *mem,
			    int log_all)
{
	int i;

	for (i = 0; i < d->nvqs; ++i) {
		int ok;
		mutex_lock(&d->vqs[i].mutex);
		/* If ring is inactive, will check when it's enabled. */
		if (d->vqs[i].private_data)
			ok = vq_memory_access_ok(d->vqs[i].log_base, mem,
						 log_all);
		else
			ok = 1;
		mutex_unlock(&d->vqs[i].mutex);
		if (!ok)
			return 0;
	}
	return 1;
}

static int vq_access_ok(struct vhost_dev *d, unsigned int num,
			struct vring_desc __user *desc,
			struct vring_avail __user *avail,
			struct vring_used __user *used)
{
	size_t s = vhost_has_feature(d, VIRTIO_RING_F_EVENT_IDX) ? 2 : 0;
	return access_ok(VERIFY_READ, desc, num * sizeof *desc) &&
	       access_ok(VERIFY_READ, avail,
			 sizeof *avail + num * sizeof *avail->ring + s) &&
	       access_ok(VERIFY_WRITE, used,
			sizeof *used + num * sizeof *used->ring + s);
}

/* Can we log writes? */
/* Caller should have device mutex but not vq mutex */
int vhost_log_access_ok(struct vhost_dev *dev)
{
	struct vhost_memory *mp;

	mp = rcu_dereference_protected(dev->memory,
				       lockdep_is_held(&dev->mutex));
	return memory_access_ok(dev, mp, 1);
}

/* Verify access for write logging. */
/* Caller should have vq mutex and device mutex */
static int vq_log_access_ok(struct vhost_dev *d, struct vhost_virtqueue *vq,
			    void __user *log_base)
{
	struct vhost_memory *mp;
	size_t s = vhost_has_feature(d, VIRTIO_RING_F_EVENT_IDX) ? 2 : 0;

	mp = rcu_dereference_protected(vq->dev->memory,
				       lockdep_is_held(&vq->mutex));
	return vq_memory_access_ok(log_base, mp,
			    vhost_has_feature(vq->dev, VHOST_F_LOG_ALL)) &&
		(!vq->log_used || log_access_ok(log_base, vq->log_addr,
					sizeof *vq->used +
					vq->num * sizeof *vq->used->ring + s));
}

/* Can we start vq? */
/* Caller should have vq mutex and device mutex */
int vhost_vq_access_ok(struct vhost_virtqueue *vq)
{
	return vq_access_ok(vq->dev, vq->num, vq->desc, vq->avail, vq->used) &&
		vq_log_access_ok(vq->dev, vq, vq->log_base);
}

static long vhost_set_memory(struct vhost_dev *d, struct vhost_memory __user *m)
{
	struct vhost_memory mem, *newmem, *oldmem;
	unsigned long size = offsetof(struct vhost_memory, regions);

	if (copy_from_user(&mem, m, size))
		return -EFAULT;
	if (mem.padding)
		return -EOPNOTSUPP;
	if (mem.nregions > VHOST_MEMORY_MAX_NREGIONS)
		return -E2BIG;
	newmem = kmalloc(size + mem.nregions * sizeof *m->regions, GFP_KERNEL);
	if (!newmem)
		return -ENOMEM;

	memcpy(newmem, &mem, size);
	if (copy_from_user(newmem->regions, m->regions,
			   mem.nregions * sizeof *m->regions)) {
		kfree(newmem);
		return -EFAULT;
	}

	if (!memory_access_ok(d, newmem,
			      vhost_has_feature(d, VHOST_F_LOG_ALL))) {
		kfree(newmem);
		return -EFAULT;
	}
	oldmem = rcu_dereference_protected(d->memory,
					   lockdep_is_held(&d->mutex));
	rcu_assign_pointer(d->memory, newmem);
	synchronize_rcu();
	kfree(oldmem);
	return 0;
}

long vhost_vring_ioctl(struct vhost_dev *d, int ioctl, void __user *argp)
{
	struct file *eventfp, *filep = NULL;
	bool pollstart = false, pollstop = false;
	struct eventfd_ctx *ctx = NULL;
	u32 __user *idxp = argp;
	struct vhost_virtqueue *vq;
	struct vhost_vring_state s;
	struct vhost_vring_file f;
	struct vhost_vring_addr a;
	u32 idx;
	long r;

	r = get_user(idx, idxp);
	if (r < 0)
		return r;
	if (idx >= d->nvqs)
		return -ENOBUFS;

	vq = d->vqs + idx;

	mutex_lock(&vq->mutex);

	switch (ioctl) {
	case VHOST_SET_VRING_NUM:
		/* Resizing ring with an active backend?
		 * You don't want to do that. */
		if (vq->private_data) {
			r = -EBUSY;
			break;
		}
		if (copy_from_user(&s, argp, sizeof s)) {
			r = -EFAULT;
			break;
		}
		if (!s.num || s.num > 0xffff || (s.num & (s.num - 1))) {
			r = -EINVAL;
			break;
		}
		vq->num = s.num;
		break;
	case VHOST_SET_VRING_BASE:
		/* Moving base with an active backend?
		 * You don't want to do that. */
		if (vq->private_data) {
			r = -EBUSY;
			break;
		}
		if (copy_from_user(&s, argp, sizeof s)) {
			r = -EFAULT;
			break;
		}
		if (s.num > 0xffff) {
			r = -EINVAL;
			break;
		}
		vq->last_avail_idx = s.num;
		/* Forget the cached index value. */
		vq->avail_idx = vq->last_avail_idx;
		break;
	case VHOST_GET_VRING_BASE:
		s.index = idx;
		s.num = vq->last_avail_idx;
		if (copy_to_user(argp, &s, sizeof s))
			r = -EFAULT;
		break;
	case VHOST_SET_VRING_ADDR:
		if (copy_from_user(&a, argp, sizeof a)) {
			r = -EFAULT;
			break;
		}
		if (a.flags & ~(0x1 << VHOST_VRING_F_LOG)) {
			r = -EOPNOTSUPP;
			break;
		}
		/* For 32bit, verify that the top 32bits of the user
		   data are set to zero. */
		if ((u64)(unsigned long)a.desc_user_addr != a.desc_user_addr ||
		    (u64)(unsigned long)a.used_user_addr != a.used_user_addr ||
		    (u64)(unsigned long)a.avail_user_addr != a.avail_user_addr) {
			r = -EFAULT;
			break;
		}
		if ((a.avail_user_addr & (sizeof *vq->avail->ring - 1)) ||
		    (a.used_user_addr & (sizeof *vq->used->ring - 1)) ||
		    (a.log_guest_addr & (sizeof *vq->used->ring - 1))) {
			r = -EINVAL;
			break;
		}

		/* We only verify access here if backend is configured.
		 * If it is not, we don't as size might not have been setup.
		 * We will verify when backend is configured. */
		if (vq->private_data) {
			if (!vq_access_ok(d, vq->num,
				(void __user *)(unsigned long)a.desc_user_addr,
				(void __user *)(unsigned long)a.avail_user_addr,
				(void __user *)(unsigned long)a.used_user_addr)) {
				r = -EINVAL;
				break;
			}

			/* Also validate log access for used ring if enabled. */
			if ((a.flags & (0x1 << VHOST_VRING_F_LOG)) &&
			    !log_access_ok(vq->log_base, a.log_guest_addr,
					   sizeof *vq->used +
					   vq->num * sizeof *vq->used->ring)) {
				r = -EINVAL;
				break;
			}
		}

		vq->log_used = !!(a.flags & (0x1 << VHOST_VRING_F_LOG));
		vq->desc = (void __user *)(unsigned long)a.desc_user_addr;
		vq->avail = (void __user *)(unsigned long)a.avail_user_addr;
		vq->log_addr = a.log_guest_addr;
		vq->used = (void __user *)(unsigned long)a.used_user_addr;
		break;
	case VHOST_SET_VRING_KICK:
		if (copy_from_user(&f, argp, sizeof f)) {
			r = -EFAULT;
			break;
		}
		eventfp = f.fd == -1 ? NULL : eventfd_fget(f.fd);
		if (IS_ERR(eventfp)) {
			r = PTR_ERR(eventfp);
			break;
		}
		if (eventfp != vq->kick) {
			pollstop = (filep = vq->kick) != NULL;
			pollstart = (vq->kick = eventfp) != NULL;
		} else
			filep = eventfp;
		break;
	case VHOST_SET_VRING_CALL:
		if (copy_from_user(&f, argp, sizeof f)) {
			r = -EFAULT;
			break;
		}
		eventfp = f.fd == -1 ? NULL : eventfd_fget(f.fd);
		if (IS_ERR(eventfp)) {
			r = PTR_ERR(eventfp);
			break;
		}
		if (eventfp != vq->call) {
			filep = vq->call;
			ctx = vq->call_ctx;
			vq->call = eventfp;
			vq->call_ctx = eventfp ?
				eventfd_ctx_fileget(eventfp) : NULL;
		} else
			filep = eventfp;
		break;
	case VHOST_SET_VRING_ERR:
		if (copy_from_user(&f, argp, sizeof f)) {
			r = -EFAULT;
			break;
		}
		eventfp = f.fd == -1 ? NULL : eventfd_fget(f.fd);
		if (IS_ERR(eventfp)) {
			r = PTR_ERR(eventfp);
			break;
		}
		if (eventfp != vq->error) {
			filep = vq->error;
			vq->error = eventfp;
			ctx = vq->error_ctx;
			vq->error_ctx = eventfp ?
				eventfd_ctx_fileget(eventfp) : NULL;
		} else
			filep = eventfp;
		break;
	default:
		r = -ENOIOCTLCMD;
	}

	if (pollstop && vq->handle_kick)
		vhost_poll_stop(&vq->poll);

	if (ctx)
		eventfd_ctx_put(ctx);
	if (filep)
		fput(filep);

	if (pollstart && vq->handle_kick)
		r = vhost_poll_start(&vq->poll, vq->kick);

	mutex_unlock(&vq->mutex);

	if (pollstop && vq->handle_kick)
		vhost_poll_flush(&vq->poll);
	return r;
}

/* Caller must have device mutex */
long vhost_dev_ioctl(struct vhost_dev *d, unsigned int ioctl, void __user *argp)
{
	struct file *eventfp, *filep = NULL;
	struct eventfd_ctx *ctx = NULL;
	u64 p;
	long r;
	int i, fd;

	/* If you are not the owner, you can become one */
	if (ioctl == VHOST_SET_OWNER) {
		r = vhost_dev_set_owner(d);
		goto done;
	}

	/* You must be the owner to do anything else */
	r = vhost_dev_check_owner(d);
	if (r)
		goto done;

	switch (ioctl) {
	case VHOST_SET_MEM_TABLE:
		r = vhost_set_memory(d, argp);
		break;
	case VHOST_SET_LOG_BASE:
		if (copy_from_user(&p, argp, sizeof p)) {
			r = -EFAULT;
			break;
		}
		if ((u64)(unsigned long)p != p) {
			r = -EFAULT;
			break;
		}
		for (i = 0; i < d->nvqs; ++i) {
			struct vhost_virtqueue *vq;
			void __user *base = (void __user *)(unsigned long)p;
			vq = d->vqs + i;
			mutex_lock(&vq->mutex);
			/* If ring is inactive, will check when it's enabled. */
			if (vq->private_data && !vq_log_access_ok(d, vq, base))
				r = -EFAULT;
			else
				vq->log_base = base;
			mutex_unlock(&vq->mutex);
		}
		break;
	case VHOST_SET_LOG_FD:
		r = get_user(fd, (int __user *)argp);
		if (r < 0)
			break;
		eventfp = fd == -1 ? NULL : eventfd_fget(fd);
		if (IS_ERR(eventfp)) {
			r = PTR_ERR(eventfp);
			break;
		}
		if (eventfp != d->log_file) {
			filep = d->log_file;
			ctx = d->log_ctx;
			d->log_ctx = eventfp ?
				eventfd_ctx_fileget(eventfp) : NULL;
		} else
			filep = eventfp;
		for (i = 0; i < d->nvqs; ++i) {
			mutex_lock(&d->vqs[i].mutex);
			d->vqs[i].log_ctx = d->log_ctx;
			mutex_unlock(&d->vqs[i].mutex);
		}
		if (ctx)
			eventfd_ctx_put(ctx);
		if (filep)
			fput(filep);
		break;
	default:
		r = -ENOIOCTLCMD;
		break;
	}
done:
	return r;
}

static const struct vhost_memory_region *find_region(struct vhost_memory *mem,
						     __u64 addr, __u32 len)
{
	struct vhost_memory_region *reg;
	int i;

	/* linear search is not brilliant, but we really have on the order of 6
	 * regions in practice */
	for (i = 0; i < mem->nregions; ++i) {
		reg = mem->regions + i;
		if (reg->guest_phys_addr <= addr &&
		    reg->guest_phys_addr + reg->memory_size - 1 >= addr)
			return reg;
	}
	return NULL;
}

/* TODO: This is really inefficient.  We need something like get_user()
 * (instruction directly accesses the data, with an exception table entry
 * returning -EFAULT). See Documentation/x86/exception-tables.txt.
 */
static int set_bit_to_user(int nr, void __user *addr)
{
	unsigned long log = (unsigned long)addr;
	struct page *page;
	void *base;
	int bit = nr + (log % PAGE_SIZE) * 8;
	int r;

	r = get_user_pages_fast(log, 1, 1, &page);
	if (r < 0)
		return r;
	BUG_ON(r != 1);
	base = kmap_atomic(page);
	set_bit(bit, base);
	kunmap_atomic(base);
	set_page_dirty_lock(page);
	put_page(page);
	return 0;
}

static int log_write(void __user *log_base,
		     u64 write_address, u64 write_length)
{
	u64 write_page = write_address / VHOST_PAGE_SIZE;
	int r;

	if (!write_length)
		return 0;
	write_length += write_address % VHOST_PAGE_SIZE;
	for (;;) {
		u64 base = (u64)(unsigned long)log_base;
		u64 log = base + write_page / 8;
		int bit = write_page % 8;
		if ((u64)(unsigned long)log != log)
			return -EFAULT;
		r = set_bit_to_user(bit, (void __user *)(unsigned long)log);
		if (r < 0)
			return r;
		if (write_length <= VHOST_PAGE_SIZE)
			break;
		write_length -= VHOST_PAGE_SIZE;
		write_page += 1;
	}
	return r;
}

int vhost_log_write(struct vhost_virtqueue *vq, struct vhost_log *log,
		    unsigned int log_num, u64 len)
{
	int i, r;

	/* Make sure data written is seen before log. */
	smp_wmb();
	for (i = 0; i < log_num; ++i) {
		u64 l = min(log[i].len, len);
		r = log_write(vq->log_base, log[i].addr, l);
		if (r < 0)
			return r;
		len -= l;
		if (!len) {
			if (vq->log_ctx)
				eventfd_signal(vq->log_ctx, 1);
			return 0;
		}
	}
	/* Length written exceeds what we have stored. This is a bug. */
	BUG();
	return 0;
}

static int vhost_update_used_flags(struct vhost_virtqueue *vq)
{
	void __user *used;
	if (__put_user(vq->used_flags, &vq->used->flags) < 0)
		return -EFAULT;
	if (unlikely(vq->log_used)) {
		/* Make sure the flag is seen before log. */
		smp_wmb();
		/* Log used flag write. */
		used = &vq->used->flags;
		log_write(vq->log_base, vq->log_addr +
			  (used - (void __user *)vq->used),
			  sizeof vq->used->flags);
		if (vq->log_ctx)
			eventfd_signal(vq->log_ctx, 1);
	}
	return 0;
}

static int vhost_update_avail_event(struct vhost_virtqueue *vq, u16 avail_event)
{
	if (__put_user(vq->avail_idx, vhost_avail_event(vq)))
		return -EFAULT;
	if (unlikely(vq->log_used)) {
		void __user *used;
		/* Make sure the event is seen before log. */
		smp_wmb();
		/* Log avail event write */
		used = vhost_avail_event(vq);
		log_write(vq->log_base, vq->log_addr +
			  (used - (void __user *)vq->used),
			  sizeof *vhost_avail_event(vq));
		if (vq->log_ctx)
			eventfd_signal(vq->log_ctx, 1);
	}
	return 0;
}

int vhost_init_used(struct vhost_virtqueue *vq)
{
	int r;
	if (!vq->private_data)
		return 0;

	r = vhost_update_used_flags(vq);
	if (r)
		return r;
	vq->signalled_used_valid = false;
	return get_user(vq->last_used_idx, &vq->used->idx);
}

static int translate_desc(struct vhost_dev *dev, u64 addr, u32 len,
			  struct iovec iov[], int iov_size)
{
	const struct vhost_memory_region *reg;
	struct vhost_memory *mem;
	struct iovec *_iov;
	u64 s = 0;
	int ret = 0;

	rcu_read_lock();

	mem = rcu_dereference(dev->memory);
	while ((u64)len > s) {
		u64 size;
		if (unlikely(ret >= iov_size)) {
			ret = -ENOBUFS;
			break;
		}
		reg = find_region(mem, addr, len);
		if (unlikely(!reg)) {
			ret = -EFAULT;
			break;
		}
		_iov = iov + ret;
		size = reg->memory_size - addr + reg->guest_phys_addr;
		_iov->iov_len = min((u64)len - s, size);
		_iov->iov_base = (void __user *)(unsigned long)
			(reg->userspace_addr + addr - reg->guest_phys_addr);
		s += size;
		addr += size;
		++ret;
	}

	rcu_read_unlock();
	return ret;
}

/* Each buffer in the virtqueues is actually a chain of descriptors.  This
 * function returns the next descriptor in the chain,
 * or -1U if we're at the end. */
static unsigned next_desc(struct vring_desc *desc)
{
	unsigned int next;

	/* If this descriptor says it doesn't chain, we're done. */
	if (!(desc->flags & VRING_DESC_F_NEXT))
		return -1U;

	/* Check they're not leading us off end of descriptors. */
	next = desc->next;
	/* Make sure compiler knows to grab that: we don't want it changing! */
	/* We will use the result as an index in an array, so most
	 * architectures only need a compiler barrier here. */
	read_barrier_depends();

	return next;
}

static int get_indirect(struct vhost_dev *dev, struct vhost_virtqueue *vq,
			struct iovec iov[], unsigned int iov_size,
			unsigned int *out_num, unsigned int *in_num,
			struct vhost_log *log, unsigned int *log_num,
			struct vring_desc *indirect)
{
	struct vring_desc desc;
	unsigned int i = 0, count, found = 0;
	int ret;

	/* Sanity check */
	if (unlikely(indirect->len % sizeof desc)) {
		vq_err(vq, "Invalid length in indirect descriptor: "
		       "len 0x%llx not multiple of 0x%zx\n",
		       (unsigned long long)indirect->len,
		       sizeof desc);
		return -EINVAL;
	}

	ret = translate_desc(dev, indirect->addr, indirect->len, vq->indirect,
			     UIO_MAXIOV);
	if (unlikely(ret < 0)) {
		vq_err(vq, "Translation failure %d in indirect.\n", ret);
		return ret;
	}

	/* We will use the result as an address to read from, so most
	 * architectures only need a compiler barrier here. */
	read_barrier_depends();

	count = indirect->len / sizeof desc;
	/* Buffers are chained via a 16 bit next field, so
	 * we can have at most 2^16 of these. */
	if (unlikely(count > USHRT_MAX + 1)) {
		vq_err(vq, "Indirect buffer length too big: %d\n",
		       indirect->len);
		return -E2BIG;
	}

	do {
		unsigned iov_count = *in_num + *out_num;
		if (unlikely(++found > count)) {
			vq_err(vq, "Loop detected: last one at %u "
			       "indirect size %u\n",
			       i, count);
			return -EINVAL;
		}
		if (unlikely(memcpy_fromiovec((unsigned char *)&desc,
					      vq->indirect, sizeof desc))) {
			vq_err(vq, "Failed indirect descriptor: idx %d, %zx\n",
			       i, (size_t)indirect->addr + i * sizeof desc);
			return -EINVAL;
		}
		if (unlikely(desc.flags & VRING_DESC_F_INDIRECT)) {
			vq_err(vq, "Nested indirect descriptor: idx %d, %zx\n",
			       i, (size_t)indirect->addr + i * sizeof desc);
			return -EINVAL;
		}

		ret = translate_desc(dev, desc.addr, desc.len, iov + iov_count,
				     iov_size - iov_count);
		if (unlikely(ret < 0)) {
			vq_err(vq, "Translation failure %d indirect idx %d\n",
			       ret, i);
			return ret;
		}
		/* If this is an input descriptor, increment that count. */
		if (desc.flags & VRING_DESC_F_WRITE) {
			*in_num += ret;
			if (unlikely(log)) {
				log[*log_num].addr = desc.addr;
				log[*log_num].len = desc.len;
				++*log_num;
			}
		} else {
			/* If it's an output descriptor, they're all supposed
			 * to come before any input descriptors. */
			if (unlikely(*in_num)) {
				vq_err(vq, "Indirect descriptor "
				       "has out after in: idx %d\n", i);
				return -EINVAL;
			}
			*out_num += ret;
		}
	} while ((i = next_desc(&desc)) != -1);
	return 0;
}

/* This looks in the virtqueue and for the first available buffer, and converts
 * it to an iovec for convenient access.  Since descriptors consist of some
 * number of output then some number of input descriptors, it's actually two
 * iovecs, but we pack them into one and note how many of each there were.
 *
 * This function returns the descriptor number found, or vq->num (which is
 * never a valid descriptor number) if none was found.  A negative code is
 * returned on error. */
int vhost_get_vq_desc(struct vhost_dev *dev, struct vhost_virtqueue *vq,
		      struct iovec iov[], unsigned int iov_size,
		      unsigned int *out_num, unsigned int *in_num,
		      struct vhost_log *log, unsigned int *log_num)
{
	struct vring_desc desc;
	unsigned int i, head, found = 0;
	u16 last_avail_idx;
	int ret;

	/* Check it isn't doing very strange things with descriptor numbers. */
	last_avail_idx = vq->last_avail_idx;
	if (unlikely(__get_user(vq->avail_idx, &vq->avail->idx))) {
		vq_err(vq, "Failed to access avail idx at %p\n",
		       &vq->avail->idx);
		return -EFAULT;
	}

	if (unlikely((u16)(vq->avail_idx - last_avail_idx) > vq->num)) {
		vq_err(vq, "Guest moved used index from %u to %u",
		       last_avail_idx, vq->avail_idx);
		return -EFAULT;
	}

	/* If there's nothing new since last we looked, return invalid. */
	if (vq->avail_idx == last_avail_idx)
		return vq->num;

	/* Only get avail ring entries after they have been exposed by guest. */
	smp_rmb();

	/* Grab the next descriptor number they're advertising, and increment
	 * the index we've seen. */
	if (unlikely(__get_user(head,
				&vq->avail->ring[last_avail_idx % vq->num]))) {
		vq_err(vq, "Failed to read head: idx %d address %p\n",
		       last_avail_idx,
		       &vq->avail->ring[last_avail_idx % vq->num]);
		return -EFAULT;
	}

	/* If their number is silly, that's an error. */
	if (unlikely(head >= vq->num)) {
		vq_err(vq, "Guest says index %u > %u is available",
		       head, vq->num);
		return -EINVAL;
	}

	/* When we start there are none of either input nor output. */
	*out_num = *in_num = 0;
	if (unlikely(log))
		*log_num = 0;

	i = head;
	do {
		unsigned iov_count = *in_num + *out_num;
		if (unlikely(i >= vq->num)) {
			vq_err(vq, "Desc index is %u > %u, head = %u",
			       i, vq->num, head);
			return -EINVAL;
		}
		if (unlikely(++found > vq->num)) {
			vq_err(vq, "Loop detected: last one at %u "
			       "vq size %u head %u\n",
			       i, vq->num, head);
			return -EINVAL;
		}
		ret = __copy_from_user(&desc, vq->desc + i, sizeof desc);
		if (unlikely(ret)) {
			vq_err(vq, "Failed to get descriptor: idx %d addr %p\n",
			       i, vq->desc + i);
			return -EFAULT;
		}
		if (desc.flags & VRING_DESC_F_INDIRECT) {
			ret = get_indirect(dev, vq, iov, iov_size,
					   out_num, in_num,
					   log, log_num, &desc);
			if (unlikely(ret < 0)) {
				vq_err(vq, "Failure detected "
				       "in indirect descriptor at idx %d\n", i);
				return ret;
			}
			continue;
		}

		ret = translate_desc(dev, desc.addr, desc.len, iov + iov_count,
				     iov_size - iov_count);
		if (unlikely(ret < 0)) {
			vq_err(vq, "Translation failure %d descriptor idx %d\n",
			       ret, i);
			return ret;
		}
		if (desc.flags & VRING_DESC_F_WRITE) {
			/* If this is an input descriptor,
			 * increment that count. */
			*in_num += ret;
			if (unlikely(log)) {
				log[*log_num].addr = desc.addr;
				log[*log_num].len = desc.len;
				++*log_num;
			}
		} else {
			/* If it's an output descriptor, they're all supposed
			 * to come before any input descriptors. */
			if (unlikely(*in_num)) {
				vq_err(vq, "Descriptor has out after in: "
				       "idx %d\n", i);
				return -EINVAL;
			}
			*out_num += ret;
		}
	} while ((i = next_desc(&desc)) != -1);

	/* On success, increment avail index. */
	vq->last_avail_idx++;

	/* Assume notifications from guest are disabled at this point,
	 * if they aren't we would need to update avail_event index. */
	BUG_ON(!(vq->used_flags & VRING_USED_F_NO_NOTIFY));
	return head;
}

/* Reverse the effect of vhost_get_vq_desc. Useful for error handling. */
void vhost_discard_vq_desc(struct vhost_virtqueue *vq, int n)
{
	vq->last_avail_idx -= n;
}

/* After we've used one of their buffers, we tell them about it.  We'll then
 * want to notify the guest, using eventfd. */
int vhost_add_used(struct vhost_virtqueue *vq, unsigned int head, int len)
{
	struct vring_used_elem __user *used;

	/* The virtqueue contains a ring of used buffers.  Get a pointer to the
	 * next entry in that used ring. */
	used = &vq->used->ring[vq->last_used_idx % vq->num];
	if (__put_user(head, &used->id)) {
		vq_err(vq, "Failed to write used id");
		return -EFAULT;
	}
	if (__put_user(len, &used->len)) {
		vq_err(vq, "Failed to write used len");
		return -EFAULT;
	}
	/* Make sure buffer is written before we update index. */
	smp_wmb();
	if (__put_user(vq->last_used_idx + 1, &vq->used->idx)) {
		vq_err(vq, "Failed to increment used idx");
		return -EFAULT;
	}
	if (unlikely(vq->log_used)) {
		/* Make sure data is seen before log. */
		smp_wmb();
		/* Log used ring entry write. */
		log_write(vq->log_base,
			  vq->log_addr +
			   ((void __user *)used - (void __user *)vq->used),
			  sizeof *used);
		/* Log used index update. */
		log_write(vq->log_base,
			  vq->log_addr + offsetof(struct vring_used, idx),
			  sizeof vq->used->idx);
		if (vq->log_ctx)
			eventfd_signal(vq->log_ctx, 1);
	}
	vq->last_used_idx++;
	/* If the driver never bothers to signal in a very long while,
	 * used index might wrap around. If that happens, invalidate
	 * signalled_used index we stored. TODO: make sure driver
	 * signals at least once in 2^16 and remove this. */
	if (unlikely(vq->last_used_idx == vq->signalled_used))
		vq->signalled_used_valid = false;
	return 0;
}

static int __vhost_add_used_n(struct vhost_virtqueue *vq,
			    struct vring_used_elem *heads,
			    unsigned count)
{
	struct vring_used_elem __user *used;
	u16 old, new;
	int start;

	start = vq->last_used_idx % vq->num;
	used = vq->used->ring + start;
	if (__copy_to_user(used, heads, count * sizeof *used)) {
		vq_err(vq, "Failed to write used");
		return -EFAULT;
	}
	if (unlikely(vq->log_used)) {
		/* Make sure data is seen before log. */
		smp_wmb();
		/* Log used ring entry write. */
		log_write(vq->log_base,
			  vq->log_addr +
			   ((void __user *)used - (void __user *)vq->used),
			  count * sizeof *used);
	}
	old = vq->last_used_idx;
	new = (vq->last_used_idx += count);
	/* If the driver never bothers to signal in a very long while,
	 * used index might wrap around. If that happens, invalidate
	 * signalled_used index we stored. TODO: make sure driver
	 * signals at least once in 2^16 and remove this. */
	if (unlikely((u16)(new - vq->signalled_used) < (u16)(new - old)))
		vq->signalled_used_valid = false;
	return 0;
}

/* After we've used one of their buffers, we tell them about it.  We'll then
 * want to notify the guest, using eventfd. */
int vhost_add_used_n(struct vhost_virtqueue *vq, struct vring_used_elem *heads,
		     unsigned count)
{
	int start, n, r;

	start = vq->last_used_idx % vq->num;
	n = vq->num - start;
	if (n < count) {
		r = __vhost_add_used_n(vq, heads, n);
		if (r < 0)
			return r;
		heads += n;
		count -= n;
	}
	r = __vhost_add_used_n(vq, heads, count);

	/* Make sure buffer is written before we update index. */
	smp_wmb();
	if (put_user(vq->last_used_idx, &vq->used->idx)) {
		vq_err(vq, "Failed to increment used idx");
		return -EFAULT;
	}
	if (unlikely(vq->log_used)) {
		/* Log used index update. */
		log_write(vq->log_base,
			  vq->log_addr + offsetof(struct vring_used, idx),
			  sizeof vq->used->idx);
		if (vq->log_ctx)
			eventfd_signal(vq->log_ctx, 1);
	}
	return r;
}

static bool vhost_notify(struct vhost_dev *dev, struct vhost_virtqueue *vq)
{
	__u16 old, new, event;
	bool v;
	/* Flush out used index updates. This is paired
	 * with the barrier that the Guest executes when enabling
	 * interrupts. */
	smp_mb();

	if (vhost_has_feature(dev, VIRTIO_F_NOTIFY_ON_EMPTY) &&
	    unlikely(vq->avail_idx == vq->last_avail_idx))
		return true;

	if (!vhost_has_feature(dev, VIRTIO_RING_F_EVENT_IDX)) {
		__u16 flags;
		if (__get_user(flags, &vq->avail->flags)) {
			vq_err(vq, "Failed to get flags");
			return true;
		}
		return !(flags & VRING_AVAIL_F_NO_INTERRUPT);
	}
	old = vq->signalled_used;
	v = vq->signalled_used_valid;
	new = vq->signalled_used = vq->last_used_idx;
	vq->signalled_used_valid = true;

	if (unlikely(!v))
		return true;

	if (get_user(event, vhost_used_event(vq))) {
		vq_err(vq, "Failed to get used event idx");
		return true;
	}
	return vring_need_event(event, new, old);
}

/* This actually signals the guest, using eventfd. */
void vhost_signal(struct vhost_dev *dev, struct vhost_virtqueue *vq)
{
	/* Signal the Guest tell them we used something up. */
	if (vq->call_ctx && vhost_notify(dev, vq))
		eventfd_signal(vq->call_ctx, 1);
}

/* And here's the combo meal deal.  Supersize me! */
void vhost_add_used_and_signal(struct vhost_dev *dev,
			       struct vhost_virtqueue *vq,
			       unsigned int head, int len)
{
	vhost_add_used(vq, head, len);
	vhost_signal(dev, vq);
}

/* multi-buffer version of vhost_add_used_and_signal */
void vhost_add_used_and_signal_n(struct vhost_dev *dev,
				 struct vhost_virtqueue *vq,
				 struct vring_used_elem *heads, unsigned count)
{
	vhost_add_used_n(vq, heads, count);
	vhost_signal(dev, vq);
}

/* OK, now we need to know about added descriptors. */
bool vhost_enable_notify(struct vhost_dev *dev, struct vhost_virtqueue *vq)
{
	u16 avail_idx;
	int r;

	/* In polling mode, when the backend (e.g., net.c) asks to enable
	 * notifications, we don't enable guest notifications. Instead, start
	 * polling on this vq by adding it to the round-robin list.
	 */
	if (vq->vqpoll.enabled) {
		if (list_empty(&vq->vqpoll.link)) {
			list_add_tail(&vq->vqpoll.link,
				&vq->dev->worker->vqpoll_list);
			vq->vqpoll.jiffies_last_kick = jiffies;
		}
		return false;
	}

	if (!(vq->used_flags & VRING_USED_F_NO_NOTIFY))
		return false;
	vq->used_flags &= ~VRING_USED_F_NO_NOTIFY;
	if (!vhost_has_feature(dev, VIRTIO_RING_F_EVENT_IDX)) {
		r = vhost_update_used_flags(vq);
		if (r) {
			vq_err(vq, "Failed to enable notification at %p: %d\n",
			       &vq->used->flags, r);
			return false;
		}
	} else {
		r = vhost_update_avail_event(vq, vq->avail_idx);
		if (r) {
			vq_err(vq, "Failed to update avail event index at %p: %d\n",
			       vhost_avail_event(vq), r);
			return false;
		}
	}
	/* They could have slipped one in as we were doing that: make
	 * sure it's written, then check again. */
	smp_mb();
	r = __get_user(avail_idx, &vq->avail->idx);
	if (r) {
		vq_err(vq, "Failed to check avail idx at %p: %d\n",
		       &vq->avail->idx, r);
		return false;
	}

	return avail_idx != vq->avail_idx;
}

/* We don't need to be notified again. */
void vhost_disable_notify(struct vhost_dev *dev, struct vhost_virtqueue *vq)
{
	int r;

	/* If this virtqueue is vqpoll.enabled, and on the polling list, it
	 * will generate notifications even if the guest is asked not to send
	 * them. So we must remove it from the round-robin polling list.
	 * Note that vqpoll.enabled remains set.
	 */
	if (vq->vqpoll.enabled) {
		if(!list_empty(&vq->vqpoll.link))
			list_del_init(&vq->vqpoll.link);
		return;
	}

	if (vq->used_flags & VRING_USED_F_NO_NOTIFY)
		return;
	vq->used_flags |= VRING_USED_F_NO_NOTIFY;
	if (!vhost_has_feature(dev, VIRTIO_RING_F_EVENT_IDX)) {
		r = vhost_update_used_flags(vq);
		if (r)
			vq_err(vq, "Failed to enable notification at %p: %d\n",
			       &vq->used->flags, r);
	}
}

static void vhost_zerocopy_done_signal(struct kref *kref)
{
	struct vhost_ubuf_ref *ubufs = container_of(kref, struct vhost_ubuf_ref,
						    kref);
	wake_up(&ubufs->wait);
}

struct vhost_ubuf_ref *vhost_ubuf_alloc(struct vhost_virtqueue *vq,
					bool zcopy)
{
	struct vhost_ubuf_ref *ubufs;
	/* No zero copy backend? Nothing to count. */
	if (!zcopy)
		return NULL;
	ubufs = kmalloc(sizeof *ubufs, GFP_KERNEL);
	if (!ubufs)
		return ERR_PTR(-ENOMEM);
	kref_init(&ubufs->kref);
	init_waitqueue_head(&ubufs->wait);
	ubufs->vq = vq;
	return ubufs;
}

void vhost_ubuf_put(struct vhost_ubuf_ref *ubufs)
{
	kref_put(&ubufs->kref, vhost_zerocopy_done_signal);
}

void vhost_ubuf_put_and_wait(struct vhost_ubuf_ref *ubufs)
{
	kref_put(&ubufs->kref, vhost_zerocopy_done_signal);
	wait_event(ubufs->wait, !atomic_read(&ubufs->kref.refcount));
	kfree(ubufs);
}
