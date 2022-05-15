/*
 * kernel/sched/debug.c
 *
 * Print the CFS rbtree
 *
 * Copyright(C) 2007, Red Hat, Inc., Ingo Molnar
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/proc_fs.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/seq_file.h>
#include <linux/kallsyms.h>
#include <linux/utsname.h>
#include <linux/mempolicy.h>
#include <linux/debugfs.h>

#include "sched.h"
/* sched: aee for sched/debug */
/* #define TEST_SCHED_DEBUG_ENHANCEMENT */
#define TRYLOCK_NUM 10
#include <linux/delay.h>

static DEFINE_SPINLOCK(sched_debug_lock);
char print_at_AEE_buffer[160];
/* sched: add rt_exec_task info */
DECLARE_PER_CPU(u64, rt_throttling_start);
DECLARE_PER_CPU(u64, exec_delta_time);
DECLARE_PER_CPU(u64, clock_task);
DECLARE_PER_CPU(u64, exec_start);
DECLARE_PER_CPU(struct task_struct, exec_task);
DECLARE_PER_CPU(u64, old_rt_time);
DECLARE_PER_CPU(u64, init_rt_time);
DECLARE_PER_CPU(u64, rt_period_time);

/*
 * This allows printing both to /proc/sched_debug and
 * to the console
 */
#define SEQ_printf(m, x...)			\
 do {						\
	if (m)					\
		seq_printf(m, x);		\
	else					\
		printk(x);			\
 } while (0)

#define SEQ_printf_at_AEE(m, x...)		\
do {						\
	snprintf(print_at_AEE_buffer, sizeof(print_at_AEE_buffer), x);	\
	aee_sram_fiq_log(print_at_AEE_buffer);	\
} while (0)
/*
 * Ease the printing of nsec fields:
 */
static long long nsec_high(unsigned long long nsec)
{
	if ((long long)nsec < 0) {
		nsec = -nsec;
		do_div(nsec, 1000000);
		return -nsec;
	}
	do_div(nsec, 1000000);

	return nsec;
}

static unsigned long nsec_low(unsigned long long nsec)
{
	if ((long long)nsec < 0)
		nsec = -nsec;

	return do_div(nsec, 1000000);
}

#define SPLIT_NS(x) nsec_high(x), nsec_low(x)

#define SCHED_FEAT(name, enabled)	\
	#name ,

static const char * const sched_feat_names[] = {
#include "features.h"
};

#undef SCHED_FEAT

static int sched_feat_show(struct seq_file *m, void *v)
{
	int i;

	for (i = 0; i < __SCHED_FEAT_NR; i++) {
		if (!(sysctl_sched_features & (1UL << i)))
			seq_puts(m, "NO_");
		seq_printf(m, "%s ", sched_feat_names[i]);
	}
	seq_puts(m, "\n");

	return 0;
}

#ifdef HAVE_JUMP_LABEL

#define jump_label_key__true  STATIC_KEY_INIT_TRUE
#define jump_label_key__false STATIC_KEY_INIT_FALSE

#define SCHED_FEAT(name, enabled)	\
	jump_label_key__##enabled ,

struct static_key sched_feat_keys[__SCHED_FEAT_NR] = {
#include "features.h"
};

#undef SCHED_FEAT

static void sched_feat_disable(int i)
{
	static_key_disable(&sched_feat_keys[i]);
}

static void sched_feat_enable(int i)
{
	static_key_enable(&sched_feat_keys[i]);
}
#else
static void sched_feat_disable(int i) { };
static void sched_feat_enable(int i) { };
#endif /* HAVE_JUMP_LABEL */

static int sched_feat_set(char *cmp)
{
	int i;
	int neg = 0;

	if (strncmp(cmp, "NO_", 3) == 0) {
		neg = 1;
		cmp += 3;
	}

	for (i = 0; i < __SCHED_FEAT_NR; i++) {
		if (strcmp(cmp, sched_feat_names[i]) == 0) {
			if (neg) {
				sysctl_sched_features &= ~(1UL << i);
				sched_feat_disable(i);
			} else {
				sysctl_sched_features |= (1UL << i);
				sched_feat_enable(i);
			}
			break;
		}
	}

	return i;
}

static ssize_t
sched_feat_write(struct file *filp, const char __user *ubuf,
		size_t cnt, loff_t *ppos)
{
	char buf[64];
	char *cmp;
	int i;
	struct inode *inode;

	if (cnt > 63)
		cnt = 63;

	if (copy_from_user(&buf, ubuf, cnt))
		return -EFAULT;

	buf[cnt] = 0;
	cmp = strstrip(buf);

	/* Ensure the static_key remains in a consistent state */
	inode = file_inode(filp);
	inode_lock(inode);
	i = sched_feat_set(cmp);
	inode_unlock(inode);
	if (i == __SCHED_FEAT_NR)
		return -EINVAL;

	*ppos += cnt;

	return cnt;
}

static int sched_feat_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, sched_feat_show, NULL);
}

static const struct file_operations sched_feat_fops = {
	.open		= sched_feat_open,
	.write		= sched_feat_write,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

__read_mostly bool sched_debug_enabled;

static __init int sched_init_debug(void)
{
	debugfs_create_file("sched_features", 0644, NULL, NULL,
			&sched_feat_fops);

	debugfs_create_bool("sched_debug", 0644, NULL,
			&sched_debug_enabled);

	return 0;
}
late_initcall(sched_init_debug);

#ifdef CONFIG_SMP

#ifdef CONFIG_SYSCTL

static struct ctl_table sd_ctl_dir[] = {
	{
		.procname	= "sched_domain",
		.mode		= 0555,
	},
	{}
};

static struct ctl_table sd_ctl_root[] = {
	{
		.procname	= "kernel",
		.mode		= 0555,
		.child		= sd_ctl_dir,
	},
	{}
};

static struct ctl_table *sd_alloc_ctl_entry(int n)
{
	struct ctl_table *entry =
		kcalloc(n, sizeof(struct ctl_table), GFP_KERNEL);

	return entry;
}

static void sd_free_ctl_entry(struct ctl_table **tablep)
{
	struct ctl_table *entry;

	/*
	 * In the intermediate directories, both the child directory and
	 * procname are dynamically allocated and could fail but the mode
	 * will always be set. In the lowest directory the names are
	 * static strings and all have proc handlers.
	 */
	for (entry = *tablep; entry->mode; entry++) {
		if (entry->child)
			sd_free_ctl_entry(&entry->child);
		if (entry->proc_handler == NULL)
			kfree(entry->procname);
	}

	kfree(*tablep);
	*tablep = NULL;
}

static int min_load_idx = 0;
static int max_load_idx = CPU_LOAD_IDX_MAX-1;

static void
set_table_entry(struct ctl_table *entry,
		const char *procname, void *data, int maxlen,
		umode_t mode, proc_handler *proc_handler,
		bool load_idx)
{
	entry->procname = procname;
	entry->data = data;
	entry->maxlen = maxlen;
	entry->mode = mode;
	entry->proc_handler = proc_handler;

	if (load_idx) {
		entry->extra1 = &min_load_idx;
		entry->extra2 = &max_load_idx;
	}
}

static struct ctl_table *
sd_alloc_ctl_energy_table(struct sched_group_energy *sge)
{
	struct ctl_table *table = sd_alloc_ctl_entry(5);

	if (table == NULL)
		return NULL;

	set_table_entry(&table[0], "nr_idle_states", &sge->nr_idle_states,
			sizeof(int), 0644, proc_dointvec_minmax, false);
	set_table_entry(&table[1], "idle_states", &sge->idle_states[0].power,
			sge->nr_idle_states*sizeof(struct idle_state), 0644,
			proc_doulongvec_minmax, false);
	set_table_entry(&table[2], "nr_cap_states", &sge->nr_cap_states,
			sizeof(int), 0644, proc_dointvec_minmax, false);
	set_table_entry(&table[3], "cap_states", &sge->cap_states[0].cap,
			sge->nr_cap_states*sizeof(struct capacity_state), 0644,
			proc_doulongvec_minmax, false);

	return table;
}

static struct ctl_table *
sd_alloc_ctl_group_table(struct sched_group *sg)
{
	struct ctl_table *table = sd_alloc_ctl_entry(2);

	if (table == NULL)
		return NULL;

	table->procname = kstrdup("energy", GFP_KERNEL);
	table->mode = 0555;
	table->child = sd_alloc_ctl_energy_table((struct sched_group_energy *)sg->sge);

	return table;
}

static struct ctl_table *
sd_alloc_ctl_domain_table(struct sched_domain *sd)
{
	struct ctl_table *table;
	unsigned int nr_entries = 14;

	int i = 0;
	struct sched_group *sg = sd->groups;

	if (sg->sge) {
		int nr_sgs = 0;

		do {} while (nr_sgs++, sg = sg->next, sg != sd->groups);

		nr_entries += nr_sgs;
	}

	table = sd_alloc_ctl_entry(nr_entries);

	if (table == NULL)
		return NULL;

	set_table_entry(&table[0], "min_interval", &sd->min_interval,
		sizeof(long), 0644, proc_doulongvec_minmax, false);
	set_table_entry(&table[1], "max_interval", &sd->max_interval,
		sizeof(long), 0644, proc_doulongvec_minmax, false);
	set_table_entry(&table[2], "busy_idx", &sd->busy_idx,
		sizeof(int), 0644, proc_dointvec_minmax, true);
	set_table_entry(&table[3], "idle_idx", &sd->idle_idx,
		sizeof(int), 0644, proc_dointvec_minmax, true);
	set_table_entry(&table[4], "newidle_idx", &sd->newidle_idx,
		sizeof(int), 0644, proc_dointvec_minmax, true);
	set_table_entry(&table[5], "wake_idx", &sd->wake_idx,
		sizeof(int), 0644, proc_dointvec_minmax, true);
	set_table_entry(&table[6], "forkexec_idx", &sd->forkexec_idx,
		sizeof(int), 0644, proc_dointvec_minmax, true);
	set_table_entry(&table[7], "busy_factor", &sd->busy_factor,
		sizeof(int), 0644, proc_dointvec_minmax, false);
	set_table_entry(&table[8], "imbalance_pct", &sd->imbalance_pct,
		sizeof(int), 0644, proc_dointvec_minmax, false);
	set_table_entry(&table[9], "cache_nice_tries",
		&sd->cache_nice_tries,
		sizeof(int), 0644, proc_dointvec_minmax, false);
	set_table_entry(&table[10], "flags", &sd->flags,
		sizeof(int), 0644, proc_dointvec_minmax, false);
	set_table_entry(&table[11], "max_newidle_lb_cost",
		&sd->max_newidle_lb_cost,
		sizeof(long), 0644, proc_doulongvec_minmax, false);
	set_table_entry(&table[12], "name", sd->name,
		CORENAME_MAX_SIZE, 0444, proc_dostring, false);
	sg = sd->groups;
	if (sg->sge) {
		char buf[32];
		struct ctl_table *entry = &table[13];

		do {
			snprintf(buf, 32, "group%d", i);
			entry->procname = kstrdup(buf, GFP_KERNEL);
			entry->mode = 0555;
			entry->child = sd_alloc_ctl_group_table(sg);
		} while (entry++, i++, sg = sg->next, sg != sd->groups);
	}
	/* &table[nr_entries-1] is terminator */

	return table;
}

static struct ctl_table *sd_alloc_ctl_cpu_table(int cpu)
{
	struct ctl_table *entry, *table;
	struct sched_domain *sd;
	int domain_num = 0, i;
	char buf[32];

	for_each_domain(cpu, sd)
		domain_num++;
	entry = table = sd_alloc_ctl_entry(domain_num + 1);
	if (table == NULL)
		return NULL;

	i = 0;
	for_each_domain(cpu, sd) {
		snprintf(buf, 32, "domain%d", i);
		entry->procname = kstrdup(buf, GFP_KERNEL);
		entry->mode = 0555;
		entry->child = sd_alloc_ctl_domain_table(sd);
		entry++;
		i++;
	}
	return table;
}

static cpumask_var_t sd_sysctl_cpus;
static struct ctl_table_header *sd_sysctl_header;

void register_sched_domain_sysctl(void)
{
	static struct ctl_table *cpu_entries;
	static struct ctl_table **cpu_idx;
	static bool init_done = false;
	char buf[32];
	int i;

	if (!cpu_entries) {
		cpu_entries = sd_alloc_ctl_entry(num_possible_cpus() + 1);
		if (!cpu_entries)
			return;

		WARN_ON(sd_ctl_dir[0].child);
		sd_ctl_dir[0].child = cpu_entries;
	}

	if (!cpu_idx) {
		struct ctl_table *e = cpu_entries;

		cpu_idx = kcalloc(nr_cpu_ids, sizeof(struct ctl_table*), GFP_KERNEL);
		if (!cpu_idx)
			return;

		/* deal with sparse possible map */
		for_each_possible_cpu(i) {
			cpu_idx[i] = e;
			e++;
		}
	}

	if (!cpumask_available(sd_sysctl_cpus)) {
		if (!alloc_cpumask_var(&sd_sysctl_cpus, GFP_KERNEL))
			return;
	}

	if (!init_done) {
		init_done = true;
		/* init to possible to not have holes in @cpu_entries */
		cpumask_copy(sd_sysctl_cpus, cpu_possible_mask);
	}

	for_each_cpu(i, sd_sysctl_cpus) {
		struct ctl_table *e = cpu_idx[i];

		if (e->child)
			sd_free_ctl_entry(&e->child);

		if (!e->procname) {
			snprintf(buf, 32, "cpu%d", i);
			e->procname = kstrdup(buf, GFP_KERNEL);
		}
		e->mode = 0555;
		e->child = sd_alloc_ctl_cpu_table(i);

		__cpumask_clear_cpu(i, sd_sysctl_cpus);
	}

	WARN_ON(sd_sysctl_header);
	sd_sysctl_header = register_sysctl_table(sd_ctl_root);
}

void dirty_sched_domain_sysctl(int cpu)
{
	if (cpumask_available(sd_sysctl_cpus))
		__cpumask_set_cpu(cpu, sd_sysctl_cpus);
}

/* may be called multiple times per register */
void unregister_sched_domain_sysctl(void)
{
	unregister_sysctl_table(sd_sysctl_header);
	sd_sysctl_header = NULL;
}
#endif /* CONFIG_SYSCTL */
#endif /* CONFIG_SMP */

#ifdef CONFIG_FAIR_GROUP_SCHED
static void print_cfs_group_stats(struct seq_file *m, int cpu, struct task_group *tg)
{
	struct sched_entity *se = tg->se[cpu];

#define P(F) \
	SEQ_printf(m, "  .%-30s: %lld\n", #F, (long long)F)
#define P_SCHEDSTAT(F) \
	SEQ_printf(m, "  .%-30s: %lld\n", #F, (long long)schedstat_val(F))
#define PN(F) \
	SEQ_printf(m, "  .%-30s: %lld.%06ld\n", #F, SPLIT_NS((long long)F))
#define PN_SCHEDSTAT(F) \
	SEQ_printf(m, "  .%-30s: %lld.%06ld\n", #F, SPLIT_NS((long long)schedstat_val(F)))

	if (!se)
		return;

	PN(se->exec_start);
	PN(se->vruntime);
	PN(se->sum_exec_runtime);
	if (schedstat_enabled()) {
		PN_SCHEDSTAT(se->statistics.wait_start);
		PN_SCHEDSTAT(se->statistics.sleep_start);
		PN_SCHEDSTAT(se->statistics.block_start);
		PN_SCHEDSTAT(se->statistics.sleep_max);
		PN_SCHEDSTAT(se->statistics.block_max);
		PN_SCHEDSTAT(se->statistics.exec_max);
		PN_SCHEDSTAT(se->statistics.slice_max);
		PN_SCHEDSTAT(se->statistics.wait_max);
		PN_SCHEDSTAT(se->statistics.wait_sum);
		P_SCHEDSTAT(se->statistics.wait_count);
	}
	P(se->load.weight);
#ifdef CONFIG_SMP
	P(se->avg.load_avg);
	P(se->avg.util_avg);
#endif

#undef PN_SCHEDSTAT
#undef PN
#undef P_SCHEDSTAT
#undef P
}
#endif

#ifdef CONFIG_CGROUP_SCHED
static char group_path[PATH_MAX];

static char *task_group_path(struct task_group *tg)
{
	if (autogroup_path(tg, group_path, PATH_MAX))
		return group_path;

	cgroup_path(tg->css.cgroup, group_path, PATH_MAX);
	return group_path;
}
#endif

static void
print_task_at_AEE(struct seq_file *m, struct rq *rq, struct task_struct *p)
{
#ifdef CONFIG_SCHEDSTATS
	if (rq->curr == p) {
#ifdef CONFIG_CGROUP_SCHED
		SEQ_printf_at_AEE(m, "R %15s %5d %9lld.%06ld %9lld %5d %9lld.%06ld %9lld.%06ld %9lld.%06ld %s\n",
			p->comm,
			task_pid_nr(p),
			SPLIT_NS(p->se.vruntime),
			(long long)(p->nvcsw + p->nivcsw),
			p->prio,
			SPLIT_NS(p->se.statistics.wait_sum),
			SPLIT_NS(p->se.sum_exec_runtime),
			SPLIT_NS(p->se.statistics.sum_sleep_runtime),
			task_group_path(task_group(p)));
#else
		SEQ_printf_at_AEE(m, "R %15s %5d %9lld.%06ld %9lld %5d %9lld.%06ld %9lld.%06ld %9lld.%06ld\n",
			p->comm,
			task_pid_nr(p),
			SPLIT_NS(p->se.vruntime),
			(long long)(p->nvcsw + p->nivcsw),
			p->prio,
			SPLIT_NS(p->se.statistics.wait_sum),
			SPLIT_NS(p->se.sum_exec_runtime),
			SPLIT_NS(p->se.statistics.sum_sleep_runtime));
#endif
	} else {
#ifdef CONFIG_CGROUP_SCHED
		SEQ_printf_at_AEE(m, "  %15s %5d %9lld.%06ld %9lld %5d %9lld.%06ld %9lld.%06ld %9lld.%06ld %s\n",
			p->comm,
			task_pid_nr(p),
			SPLIT_NS(p->se.vruntime),
			(long long)(p->nvcsw + p->nivcsw),
			p->prio,
			SPLIT_NS(p->se.statistics.wait_sum),
			SPLIT_NS(p->se.sum_exec_runtime),
			SPLIT_NS(p->se.statistics.sum_sleep_runtime),
			task_group_path(task_group(p)));
#else
		SEQ_printf_at_AEE(m, "  %15s %5d %9lld.%06ld %9lld %5d %9lld.%06ld %9lld.%06ld %9lld.%06ld\n",
			p->comm,
			task_pid_nr(p),
			SPLIT_NS(p->se.vruntime),
			(long long)(p->nvcsw + p->nivcsw),
			p->prio,
			SPLIT_NS(p->se.statistics.wait_sum),
			SPLIT_NS(p->se.sum_exec_runtime),
			SPLIT_NS(p->se.statistics.sum_sleep_runtime));
#endif
	}
#else
	SEQ_printf_at_AEE(m, "%9lld.%06ld %9lld.%06ld %9lld.%06ld",
		0LL, 0L,
		SPLIT_NS(p->se.sum_exec_runtime),
		0LL, 0L);
#endif
}

static void
print_task(struct seq_file *m, struct rq *rq, struct task_struct *p)
{
	if (rq->curr == p)
		SEQ_printf(m, ">R");
	else
		SEQ_printf(m, " %c", task_state_to_char(p));

	SEQ_printf(m, "%15s %5d %9Ld.%06ld %9Ld %5d ",
		p->comm, task_pid_nr(p),
		SPLIT_NS(p->se.vruntime),
		(long long)(p->nvcsw + p->nivcsw),
		p->prio);

	SEQ_printf(m, "%9Ld.%06ld %9Ld.%06ld %9Ld.%06ld",
		SPLIT_NS(schedstat_val_or_zero(p->se.statistics.wait_sum)),
		SPLIT_NS(p->se.sum_exec_runtime),
		SPLIT_NS(schedstat_val_or_zero(p->se.statistics.sum_sleep_runtime)));

#ifdef CONFIG_NUMA_BALANCING
	SEQ_printf(m, " %d %d", task_node(p), task_numa_group_id(p));
#endif
#ifdef CONFIG_CGROUP_SCHED
	SEQ_printf(m, " %s", task_group_path(task_group(p)));
#endif

	SEQ_printf(m, "\n");
}

static void print_rq(struct seq_file *m, struct rq *rq, int rq_cpu)
{
	struct task_struct *g, *p;

	SEQ_printf(m,
	"\nrunnable tasks:\n"
	" S           task   PID         tree-key  switches  prio"
	"     wait-time             sum-exec        sum-sleep\n"
	"-------------------------------------------------------"
	"----------------------------------------------------\n");

	rcu_read_lock();
	for_each_process_thread(g, p) {
		if (task_cpu(p) != rq_cpu)
			continue;

		print_task(m, rq, p);
	}
	rcu_read_unlock();
}

void print_cfs_rq(struct seq_file *m, int cpu, struct cfs_rq *cfs_rq)
{
	s64 MIN_vruntime = -1, min_vruntime, max_vruntime = -1,
		spread, rq0_min_vruntime, spread0;
	struct rq *rq = cpu_rq(cpu);
	struct sched_entity *last;
	unsigned long flags;

#ifdef CONFIG_FAIR_GROUP_SCHED
	SEQ_printf(m, "\ncfs_rq[%d]:%s\n", cpu, task_group_path(cfs_rq->tg));
#else
	SEQ_printf(m, "\ncfs_rq[%d]:\n", cpu);
#endif
	SEQ_printf(m, "  .%-30s: %Ld.%06ld\n", "exec_clock",
			SPLIT_NS(cfs_rq->exec_clock));

	raw_spin_lock_irqsave(&rq->lock, flags);
	if (rb_first_cached(&cfs_rq->tasks_timeline))
		MIN_vruntime = (__pick_first_entity(cfs_rq))->vruntime;
	last = __pick_last_entity(cfs_rq);
	if (last)
		max_vruntime = last->vruntime;
	min_vruntime = cfs_rq->min_vruntime;
	rq0_min_vruntime = cpu_rq(0)->cfs.min_vruntime;
	raw_spin_unlock_irqrestore(&rq->lock, flags);
	SEQ_printf(m, "  .%-30s: %Ld.%06ld\n", "MIN_vruntime",
			SPLIT_NS(MIN_vruntime));
	SEQ_printf(m, "  .%-30s: %Ld.%06ld\n", "min_vruntime",
			SPLIT_NS(min_vruntime));
	SEQ_printf(m, "  .%-30s: %Ld.%06ld\n", "max_vruntime",
			SPLIT_NS(max_vruntime));
	spread = max_vruntime - MIN_vruntime;
	SEQ_printf(m, "  .%-30s: %Ld.%06ld\n", "spread",
			SPLIT_NS(spread));
	spread0 = min_vruntime - rq0_min_vruntime;
	SEQ_printf(m, "  .%-30s: %Ld.%06ld\n", "spread0",
			SPLIT_NS(spread0));
	SEQ_printf(m, "  .%-30s: %d\n", "nr_spread_over",
			cfs_rq->nr_spread_over);
	SEQ_printf(m, "  .%-30s: %d\n", "nr_running", cfs_rq->nr_running);
	SEQ_printf(m, "  .%-30s: %ld\n", "load", cfs_rq->load.weight);
#ifdef CONFIG_SMP
	SEQ_printf(m, "  .%-30s: %lu\n", "load_avg",
			cfs_rq->avg.load_avg);
	SEQ_printf(m, "  .%-30s: %lu\n", "runnable_load_avg",
			cfs_rq->runnable_load_avg);
	SEQ_printf(m, "  .%-30s: %lu\n", "util_avg",
			cfs_rq->avg.util_avg);
	SEQ_printf(m, "  .%-30s: %u\n", "util_est_enqueued",
			cfs_rq->avg.util_est.enqueued);
	SEQ_printf(m, "  .%-30s: %ld\n", "removed_load_avg",
			atomic_long_read(&cfs_rq->removed_load_avg));
	SEQ_printf(m, "  .%-30s: %ld\n", "removed_util_avg",
			atomic_long_read(&cfs_rq->removed_util_avg));
#ifdef CONFIG_FAIR_GROUP_SCHED
	SEQ_printf(m, "  .%-30s: %lu\n", "tg_load_avg_contrib",
			cfs_rq->tg_load_avg_contrib);
	SEQ_printf(m, "  .%-30s: %ld\n", "tg_load_avg",
			atomic_long_read(&cfs_rq->tg->load_avg));
#endif
#endif
#ifdef CONFIG_CFS_BANDWIDTH
	SEQ_printf(m, "  .%-30s: %d\n", "throttled",
			cfs_rq->throttled);
	SEQ_printf(m, "  .%-30s: %d\n", "throttle_count",
			cfs_rq->throttle_count);
#endif

#ifdef CONFIG_FAIR_GROUP_SCHED
	print_cfs_group_stats(m, cpu, cfs_rq->tg);
#endif
}

void print_rt_rq(struct seq_file *m, int cpu, struct rt_rq *rt_rq)
{
#ifdef CONFIG_RT_GROUP_SCHED
	SEQ_printf(m, "\nrt_rq[%d]:%s\n", cpu, task_group_path(rt_rq->tg));
#else
	SEQ_printf(m, "\nrt_rq[%d]:\n", cpu);
#endif

#define P(x) \
	SEQ_printf(m, "  .%-30s: %Ld\n", #x, (long long)(rt_rq->x))
#define PU(x) \
	SEQ_printf(m, "  .%-30s: %lu\n", #x, (unsigned long)(rt_rq->x))
#define PN(x) \
	SEQ_printf(m, "  .%-30s: %Ld.%06ld\n", #x, SPLIT_NS(rt_rq->x))

	PU(rt_nr_running);
#ifdef CONFIG_SMP
	PU(rt_nr_migratory);
#endif
	P(rt_throttled);
	PN(rt_time);
	PN(rt_runtime);

#undef PN
#undef PU
#undef P
}

void print_dl_rq(struct seq_file *m, int cpu, struct dl_rq *dl_rq)
{
	struct dl_bw *dl_bw;

	SEQ_printf(m, "\ndl_rq[%d]:\n", cpu);

#define PU(x) \
	SEQ_printf(m, "  .%-30s: %lu\n", #x, (unsigned long)(dl_rq->x))

	PU(dl_nr_running);
#ifdef CONFIG_SMP
	PU(dl_nr_migratory);
	dl_bw = &cpu_rq(cpu)->rd->dl_bw;
#else
	dl_bw = &dl_rq->dl_bw;
#endif
	SEQ_printf(m, "  .%-30s: %lld\n", "dl_bw->bw", dl_bw->bw);
	SEQ_printf(m, "  .%-30s: %lld\n", "dl_bw->total_bw", dl_bw->total_bw);

#undef PU
}

extern __read_mostly int sched_clock_running;

static void print_cpu(struct seq_file *m, int cpu)
{
	struct rq *rq = cpu_rq(cpu);
	unsigned long flags;

#ifdef CONFIG_X86
	{
		unsigned int freq = cpu_khz ? : 1;

		SEQ_printf(m, "cpu#%d, %u.%03u MHz\n",
			   cpu, freq / 1000, (freq % 1000));
	}
#else
	/* sched: add cpu info */
	SEQ_printf(m, "cpu#%d: %s\n", cpu, cpu_is_offline(cpu)?"Offline":"Online");
#endif

#define P(x)								\
do {									\
	if (sizeof(rq->x) == 4)						\
		SEQ_printf(m, "  .%-30s: %ld\n", #x, (long)(rq->x));	\
	else								\
		SEQ_printf(m, "  .%-30s: %Ld\n", #x, (long long)(rq->x));\
} while (0)

#define PN(x) \
	SEQ_printf(m, "  .%-30s: %Ld.%06ld\n", #x, SPLIT_NS(rq->x))

	P(nr_running);
	SEQ_printf(m, "  .%-30s: %lu\n", "load",
		   rq->load.weight);
	P(nr_switches);
	P(nr_load_updates);
	P(nr_uninterruptible);
	PN(next_balance);
	SEQ_printf(m, "  .%-30s: %ld\n", "curr->pid", (long)(task_pid_nr(rq->curr)));
	PN(clock);
	PN(clock_task);
	P(cpu_load[0]);
	P(cpu_load[1]);
	P(cpu_load[2]);
	P(cpu_load[3]);
	P(cpu_load[4]);
#ifdef CONFIG_SMP
	P(cpu_capacity);
#endif
#ifdef CONFIG_SCHED_WALT
	P(cluster->load_scale_factor);
	P(cluster->capacity);
	P(cluster->max_possible_capacity);
	P(cluster->efficiency);
	P(cluster->cur_freq);
	P(cluster->max_freq);
	P(cluster->exec_scale_factor);
	P(walt_stats.nr_big_tasks);
	SEQ_printf(m, "  .%-30s: %llu\n", "walt_stats.cumulative_runnable_avg",
			rq->walt_stats.cumulative_runnable_avg_scaled);
#endif
#undef P
#undef PN

#ifdef CONFIG_SMP
#define P64(n) SEQ_printf(m, "  .%-30s: %Ld\n", #n, rq->n);
	P64(avg_idle);
	P64(max_idle_balance_cost);
#undef P64
#endif

#define P(n) SEQ_printf(m, "  .%-30s: %d\n", #n, schedstat_val(rq->n));
	if (schedstat_enabled()) {
		P(yld_count);
		P(sched_count);
		P(sched_goidle);
		P(ttwu_count);
		P(ttwu_local);
	}
#undef P

	spin_lock_irqsave(&sched_debug_lock, flags);
	print_cfs_stats(m, cpu);
	print_rt_stats(m, cpu);
	print_dl_stats(m, cpu);

	print_rq(m, rq, cpu);
	spin_unlock_irqrestore(&sched_debug_lock, flags);
	SEQ_printf(m, "\n");
}

static const char *sched_tunable_scaling_names[] = {
	"none",
	"logaritmic",
	"linear"
};

static void sched_debug_header(struct seq_file *m)
{
	u64 ktime, sched_clk, cpu_clk;
	unsigned long flags;

	local_irq_save(flags);
	ktime = ktime_to_ns(ktime_get());
	sched_clk = sched_clock();
	cpu_clk = local_clock();
	local_irq_restore(flags);

	SEQ_printf(m, "Sched Debug Version: v0.11, %s %.*s\n",
		init_utsname()->release,
		(int)strcspn(init_utsname()->version, " "),
		init_utsname()->version);

#define P(x) \
	SEQ_printf(m, "%-40s: %Ld\n", #x, (long long)(x))
#define PN(x) \
	SEQ_printf(m, "%-40s: %Ld.%06ld\n", #x, SPLIT_NS(x))
	PN(ktime);
	PN(sched_clk);
	PN(cpu_clk);
	P(jiffies);
#ifdef CONFIG_HAVE_UNSTABLE_SCHED_CLOCK
	P(sched_clock_stable());
#endif
#undef PN
#undef P

	SEQ_printf(m, "\n");
	SEQ_printf(m, "sysctl_sched\n");

#define P(x) \
	SEQ_printf(m, "  .%-40s: %Ld\n", #x, (long long)(x))
#define PN(x) \
	SEQ_printf(m, "  .%-40s: %Ld.%06ld\n", #x, SPLIT_NS(x))
	PN(sysctl_sched_latency);
	PN(sysctl_sched_min_granularity);
	PN(sysctl_sched_wakeup_granularity);
	P(sysctl_sched_child_runs_first);
	P(sysctl_sched_features);
#ifdef CONFIG_SCHED_WALT
	P(sched_init_task_load_windows);
	P(min_capacity);
	P(max_capacity);
	P(sched_ravg_window);
	P(sched_load_granule);
#endif
#undef PN
#undef P

	SEQ_printf(m, "  .%-40s: %d (%s)\n",
		"sysctl_sched_tunable_scaling",
		sysctl_sched_tunable_scaling,
		sched_tunable_scaling_names[sysctl_sched_tunable_scaling]);
	SEQ_printf(m, "\n");
}

static int sched_debug_show(struct seq_file *m, void *v)
{
	int cpu = (unsigned long)(v - 2);

	if (cpu != -1) {
		print_cpu(m, cpu);
		SEQ_printf(m, "\n");
	} else
		sched_debug_header(m);

	return 0;
}

void sysrq_sched_debug_show(void)
{
	int cpu;

	sched_debug_header(NULL);
	/* for_each_online_cpu(cpu) */
	for_each_possible_cpu(cpu)
		print_cpu(NULL, cpu);
}

/*
 * This itererator needs some explanation.
 * It returns 1 for the header position.
 * This means 2 is cpu 0.
 * In a hotplugged system some cpus, including cpu 0, may be missing so we have
 * to use cpumask_* to iterate over the cpus.
 */
static void *sched_debug_start(struct seq_file *file, loff_t *offset)
{
	unsigned long n = *offset;

	if (n == 0)
		return (void *) 1;

	n--;

	if (n > 0)
		n = cpumask_next(n - 1, cpu_online_mask);
	else
		n = cpumask_first(cpu_online_mask);

	*offset = n + 1;

	if (n < nr_cpu_ids)
		return (void *)(unsigned long)(n + 2);
	return NULL;
}

static void *sched_debug_next(struct seq_file *file, void *data, loff_t *offset)
{
	(*offset)++;
	return sched_debug_start(file, offset);
}

static void sched_debug_stop(struct seq_file *file, void *data)
{
}

static const struct seq_operations sched_debug_sops = {
	.start = sched_debug_start,
	.next = sched_debug_next,
	.stop = sched_debug_stop,
	.show = sched_debug_show,
};

static int sched_debug_release(struct inode *inode, struct file *file)
{
	seq_release(inode, file);

	return 0;
}

static int sched_debug_open(struct inode *inode, struct file *filp)
{
	int ret = 0;

	ret = seq_open(filp, &sched_debug_sops);

	return ret;
}

static const struct file_operations sched_debug_fops = {
	.open		= sched_debug_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= sched_debug_release,
};

static int __init init_sched_debug_procfs(void)
{
	struct proc_dir_entry *pe;

	pe = proc_create("sched_debug", 0444, NULL, &sched_debug_fops);
	if (!pe)
		return -ENOMEM;
	return 0;
}

__initcall(init_sched_debug_procfs);

#define __P(F) \
	SEQ_printf(m, "%-45s:%21Ld\n", #F, (long long)F)
#define P(F) \
	SEQ_printf(m, "%-45s:%21Ld\n", #F, (long long)p->F)
#define __PN(F) \
	SEQ_printf(m, "%-45s:%14Ld.%06ld\n", #F, SPLIT_NS((long long)F))
#define PN(F) \
	SEQ_printf(m, "%-45s:%14Ld.%06ld\n", #F, SPLIT_NS((long long)p->F))


#ifdef CONFIG_NUMA_BALANCING
void print_numa_stats(struct seq_file *m, int node, unsigned long tsf,
		unsigned long tpf, unsigned long gsf, unsigned long gpf)
{
	SEQ_printf(m, "numa_faults node=%d ", node);
	SEQ_printf(m, "task_private=%lu task_shared=%lu ", tsf, tpf);
	SEQ_printf(m, "group_private=%lu group_shared=%lu\n", gsf, gpf);
}
#endif


static void sched_show_numa(struct task_struct *p, struct seq_file *m)
{
#ifdef CONFIG_NUMA_BALANCING
	struct mempolicy *pol;

	if (p->mm)
		P(mm->numa_scan_seq);

	task_lock(p);
	pol = p->mempolicy;
	if (pol && !(pol->flags & MPOL_F_MORON))
		pol = NULL;
	mpol_get(pol);
	task_unlock(p);

	P(numa_pages_migrated);
	P(numa_preferred_nid);
	P(total_numa_faults);
	SEQ_printf(m, "current_node=%d, numa_group_id=%d\n",
			task_node(p), task_numa_group_id(p));
	show_numa_stats(p, m);
	mpol_put(pol);
#endif
}

void proc_sched_show_task(struct task_struct *p, struct pid_namespace *ns,
						  struct seq_file *m)
{
	unsigned long nr_switches;

	SEQ_printf(m, "%s (%d, #threads: %d)\n", p->comm, task_pid_nr_ns(p, ns),
						get_nr_threads(p));
	SEQ_printf(m,
		"---------------------------------------------------------"
		"----------\n");
#define __P(F) \
	SEQ_printf(m, "%-45s:%21Ld\n", #F, (long long)F)
#define P(F) \
	SEQ_printf(m, "%-45s:%21Ld\n", #F, (long long)p->F)
#define P_SCHEDSTAT(F) \
	SEQ_printf(m, "%-45s:%21Ld\n", #F, (long long)schedstat_val(p->F))
#define __PN(F) \
	SEQ_printf(m, "%-45s:%14Ld.%06ld\n", #F, SPLIT_NS((long long)F))
#define PN(F) \
	SEQ_printf(m, "%-45s:%14Ld.%06ld\n", #F, SPLIT_NS((long long)p->F))
#define PN_SCHEDSTAT(F) \
	SEQ_printf(m, "%-45s:%14Ld.%06ld\n", #F, SPLIT_NS((long long)schedstat_val(p->F)))

	PN(se.exec_start);
	PN(se.vruntime);
	PN(se.sum_exec_runtime);

	nr_switches = p->nvcsw + p->nivcsw;

	P(se.nr_migrations);

	if (schedstat_enabled()) {
		u64 avg_atom, avg_per_cpu;

		PN_SCHEDSTAT(se.statistics.sum_sleep_runtime);
		PN_SCHEDSTAT(se.statistics.wait_start);
		PN_SCHEDSTAT(se.statistics.sleep_start);
		PN_SCHEDSTAT(se.statistics.block_start);
		PN_SCHEDSTAT(se.statistics.sleep_max);
		PN_SCHEDSTAT(se.statistics.block_max);
		PN_SCHEDSTAT(se.statistics.exec_max);
		PN_SCHEDSTAT(se.statistics.slice_max);
		PN_SCHEDSTAT(se.statistics.wait_max);
		PN_SCHEDSTAT(se.statistics.wait_sum);
		P_SCHEDSTAT(se.statistics.wait_count);
		PN_SCHEDSTAT(se.statistics.iowait_sum);
		P_SCHEDSTAT(se.statistics.iowait_count);
		P_SCHEDSTAT(se.statistics.nr_migrations_cold);
		P_SCHEDSTAT(se.statistics.nr_failed_migrations_affine);
		P_SCHEDSTAT(se.statistics.nr_failed_migrations_running);
		P_SCHEDSTAT(se.statistics.nr_failed_migrations_hot);
		P_SCHEDSTAT(se.statistics.nr_forced_migrations);
		P_SCHEDSTAT(se.statistics.nr_wakeups);
		P_SCHEDSTAT(se.statistics.nr_wakeups_sync);
		P_SCHEDSTAT(se.statistics.nr_wakeups_migrate);
		P_SCHEDSTAT(se.statistics.nr_wakeups_local);
		P_SCHEDSTAT(se.statistics.nr_wakeups_remote);
		P_SCHEDSTAT(se.statistics.nr_wakeups_affine);
		P_SCHEDSTAT(se.statistics.nr_wakeups_affine_attempts);
		P_SCHEDSTAT(se.statistics.nr_wakeups_passive);
		P_SCHEDSTAT(se.statistics.nr_wakeups_idle);

#ifdef CONFIG_SCHED_WALT
		P(ravg.demand);
#endif
		avg_atom = p->se.sum_exec_runtime;
		if (nr_switches)
			avg_atom = div64_ul(avg_atom, nr_switches);
		else
			avg_atom = -1LL;

		avg_per_cpu = p->se.sum_exec_runtime;
		if (p->se.nr_migrations) {
			avg_per_cpu = div64_u64(avg_per_cpu,
						p->se.nr_migrations);
		} else {
			avg_per_cpu = -1LL;
		}

		__PN(avg_atom);
		__PN(avg_per_cpu);
	}

	__P(nr_switches);
	SEQ_printf(m, "%-45s:%21Ld\n",
		   "nr_voluntary_switches", (long long)p->nvcsw);
	SEQ_printf(m, "%-45s:%21Ld\n",
		   "nr_involuntary_switches", (long long)p->nivcsw);

	P(se.load.weight);
#ifdef CONFIG_SMP
	P(se.avg.load_sum);
	P(se.avg.util_sum);
	P(se.avg.load_avg);
	P(se.avg.util_avg);
	P(se.avg.last_update_time);
	P(se.avg.util_est.ewma);
	P(se.avg.util_est.enqueued);
#endif
	P(policy);
	P(prio);
	if (p->policy == SCHED_DEADLINE) {
		P(dl.runtime);
		P(dl.deadline);
	}
#undef PN_SCHEDSTAT
#undef PN
#undef __PN
#undef P_SCHEDSTAT
#undef P
#undef __P

	{
		unsigned int this_cpu = raw_smp_processor_id();
		u64 t0, t1;

		t0 = cpu_clock(this_cpu);
		t1 = cpu_clock(this_cpu);
		SEQ_printf(m, "%-45s:%21Ld\n",
			   "clock-delta", (long long)(t1-t0));
	}

	sched_show_numa(p, m);
}

void proc_sched_set_task(struct task_struct *p)
{
#ifdef CONFIG_SCHEDSTATS
	memset(&p->se.statistics, 0, sizeof(p->se.statistics));
#endif
}
/* sched: add aee log */
#define read_trylock_irqsave(lock, flags)		\
	({						\
		typecheck(unsigned long, flags);	\
		local_irq_save(flags);			\
		read_trylock(lock) ? \
		1 : ({ local_irq_restore(flags); 0; }); \
	})

int read_trylock_n_irqsave(rwlock_t *lock, unsigned long *flags, struct seq_file *m, char *msg)
{
	int locked, trylock_cnt = 0;

	do {
		locked = read_trylock_irqsave(lock, *flags);
		trylock_cnt++;
		mdelay(10);
	} while ((!locked) && (trylock_cnt < TRYLOCK_NUM));

	if (!locked) {
#ifdef CONFIG_DEBUG_SPINLOCK
		struct task_struct *owner = NULL;
#endif
		SEQ_printf_at_AEE(m, "Warning: fail to get lock in %s\n", msg);
#ifdef CONFIG_DEBUG_SPINLOCK
		if (lock->owner && lock->owner != SPINLOCK_OWNER_INIT)
			owner = lock->owner;
#ifdef CONFIG_SMP
		SEQ_printf_at_AEE(m, " lock: %p, .magic: %08x, .owner: %s/%d",
				lock, lock->magic,
				owner ? owner->comm : "<<none>>",
				owner ? task_pid_nr(owner) : -1);
		SEQ_printf_at_AEE(m, ".owner_cpu: %d, value: %d\n",
			   lock->owner_cpu, lock->raw_lock.lock);
#else
		SEQ_printf_at_AEE(m, " lock: %p, .magic: %08x, .owner: %s/%d",
			   lock, lock->magic,
			   owner ? owner->comm : "<<none>>",
			   owner ? task_pid_nr(owner) : -1);
		SEQ_printf_at_AEE(m, ".owner_cpu: %d\n", lock->owner_cpu);
#endif
#endif
	}

	return locked;
}

int raw_spin_trylock_n_irqsave(raw_spinlock_t *lock, unsigned long *flags, struct seq_file *m, char *msg)
{
	int locked, trylock_cnt = 0;

	do {
		locked = raw_spin_trylock_irqsave(lock, *flags);
		trylock_cnt++;
		mdelay(10);
	} while ((!locked) && (trylock_cnt < TRYLOCK_NUM));

	if (!locked) {
#ifdef CONFIG_DEBUG_SPINLOCK
		struct task_struct *owner = NULL;
#endif
		SEQ_printf_at_AEE(m, "Warning: fail to get lock in %s\n", msg);
#ifdef CONFIG_DEBUG_SPINLOCK
		if (lock->owner && lock->owner != SPINLOCK_OWNER_INIT)
			owner = lock->owner;
#ifdef CONFIG_ARM64
#ifdef CONFIG_SMP
		SEQ_printf_at_AEE(m, " lock: %lx, .magic: %08x, .owner: %s/%d",
			   (long)lock, lock->magic,
			   owner ? owner->comm : "<<none>>",
			   owner ? task_pid_nr(owner) : -1);
		SEQ_printf_at_AEE(m, ".owner_cpu: %d, owner: %hu, next: %hu\n",
			   lock->owner_cpu,
			   lock->raw_lock.owner, lock->raw_lock.next);
#else
		SEQ_printf_at_AEE(m, " lock: %lx, .magic: %08x, .owner: %s/%d",
			   (long)lock, lock->magic,
			   owner ? owner->comm : "<<none>>",
			   owner ? task_pid_nr(owner) : -1);
		SEQ_printf_at_AEE(m, ".owner_cpu: %d, value: %d\n",
			   lock->owner_cpu, lock->raw_lock.slock);
#endif
#else
		SEQ_printf_at_AEE(m, " lock: %x, .magic: %08x, .owner: %s/%d",
			   (int)lock, lock->magic,
				owner ? owner->comm : "<<none>>",
				owner ? task_pid_nr(owner) : -1);
		SEQ_printf_at_AEE(m, ".owner_cpu: %d, value: %d\n",
				lock->owner_cpu, lock->raw_lock.slock);
#endif
#endif
	}

	return locked;
}

int spin_trylock_n_irqsave(spinlock_t *lock, unsigned long *flags, struct seq_file *m, char *msg)
{
	int locked, trylock_cnt = 0;

	do {
		locked = spin_trylock_irqsave(lock, *flags);
		trylock_cnt++;
		mdelay(10);

	} while ((!locked) && (trylock_cnt < TRYLOCK_NUM));

	if (!locked) {
#ifdef CONFIG_DEBUG_SPINLOCK
		raw_spinlock_t rlock = lock->rlock;
		struct task_struct *owner = NULL;
#endif
		SEQ_printf_at_AEE(m, "Warning: fail to get lock in %s\n", msg);
#ifdef CONFIG_DEBUG_SPINLOCK
		if (rlock.owner && rlock.owner != SPINLOCK_OWNER_INIT)
			owner = rlock.owner;
#ifdef CONFIG_ARM64
#ifdef CONFIG_SMP
		SEQ_printf_at_AEE(m, " lock: %lx, .magic: %08x, .owner: %s/%d",
			   (long)&rlock, rlock.magic,
			   owner ? owner->comm : "<<none>>",
			   owner ? task_pid_nr(owner) : -1);
		SEQ_printf_at_AEE(m, ".owner_cpu: %d, owner: %hu, next: %hu\n",
			   rlock.owner_cpu,
			   rlock.raw_lock.owner, rlock.raw_lock.next);
#else
		SEQ_printf_at_AEE(m, " lock: %lx, .magic: %08x, .owner: %s/%d",
			   (long)&rlock, rlock.magic,
			   owner ? owner->comm : "<<none>>",
			   owner ? task_pid_nr(owner) : -1);
		SEQ_printf_at_AEE(m, ".owner_cpu: %d, value: %d\n",
			   rlock.owner_cpu, rlock.raw_lock.slock);
#endif
#else
		SEQ_printf_at_AEE(m, " lock: %x, .magic: %08x, .owner: %s/%d",
			   (int)&rlock, rlock.magic,
			   owner ? owner->comm : "<<none>>",
			   owner ? task_pid_nr(owner) : -1);
		SEQ_printf_at_AEE(m, ".owner_cpu: %d, value: %d\n",
			    rlock.owner_cpu, rlock.raw_lock.slock);
#endif
#endif
	}

	return locked;
}
static void print_rq_at_AEE(struct seq_file *m, struct rq *rq, int rq_cpu)
{
	struct task_struct *g, *p;

	SEQ_printf_at_AEE(m, "\nrunnable tasks:\n");
	SEQ_printf_at_AEE(m,
	"            task   PID         tree-key  switches  prio     wait-time             sum-exec        sum-sleep\n");
	SEQ_printf_at_AEE(m, "---------------------------------------------------\n");

	rcu_read_lock();
	for_each_process_thread(g, p) {
		/*
		 * if (task_cpu(p) != rq_cpu)
		 * sched: only output the runnable tasks rather than ALL tasks in runqueues
		 */
		if (!p->on_rq || task_cpu(p) != rq_cpu)
			continue;

		print_task_at_AEE(m, rq, p);
	}
	rcu_read_unlock();
}

#ifdef CONFIG_FAIR_GROUP_SCHED
static void print_cfs_group_stats_at_AEE(struct seq_file *m, int cpu, struct task_group *tg)
{
	struct sched_entity *se = tg->se[cpu];

#define P(F) \
	SEQ_printf_at_AEE(m, "  .%-30s: %lld\n", #F, (long long)F)
#define PN(F) \
	SEQ_printf_at_AEE(m, "  .%-30s: %lld.%06ld\n", #F, SPLIT_NS((long long)F))

	if (!se)
		return;

	PN(se->exec_start);
	PN(se->vruntime);
	PN(se->sum_exec_runtime);
#ifdef CONFIG_SCHEDSTATS
	PN(se->statistics.wait_start);
	PN(se->statistics.sleep_start);
	PN(se->statistics.block_start);
	PN(se->statistics.sleep_max);
	PN(se->statistics.block_max);
	PN(se->statistics.exec_max);
	PN(se->statistics.slice_max);
	PN(se->statistics.wait_max);
	PN(se->statistics.wait_sum);
	P(se->statistics.wait_count);
#endif
	P(se->load.weight);
#ifdef CONFIG_SMP
	P(se->avg.load_avg);
	P(se->avg.util_avg);
#endif
#undef PN
#undef P
}
#endif

void print_cfs_rq_at_AEE(struct seq_file *m, int cpu, struct cfs_rq *cfs_rq)
{
	s64 MIN_vruntime = -1, min_vruntime, max_vruntime = -1,
		spread, rq0_min_vruntime, spread0;
	struct rq *rq = cpu_rq(cpu);
	struct sched_entity *last;
	unsigned long flags;
	int locked;
#ifdef CONFIG_FAIR_GROUP_SCHED
	SEQ_printf_at_AEE(m, "\ncfs_rq[%d]:%s\n", cpu, task_group_path(cfs_rq->tg));
#else
	SEQ_printf_at_AEE(m, "\ncfs_rq[%d]:\n", cpu);
#endif
	SEQ_printf_at_AEE(m, "  .%-30s: %lld.%06ld\n", "exec_clock",
			SPLIT_NS(cfs_rq->exec_clock));

	/*raw_spin_lock_irqsave(&rq->lock, flags);*/
	locked = raw_spin_trylock_n_irqsave(&rq->lock, &flags, m, "print_cfs_rq_at_AEE");
	if (cfs_rq->rb_leftmost)
		MIN_vruntime = (__pick_first_entity(cfs_rq))->vruntime;
	last = __pick_last_entity(cfs_rq);
	if (last)
		max_vruntime = last->vruntime;
	min_vruntime = cfs_rq->min_vruntime;
	rq0_min_vruntime = cpu_rq(0)->cfs.min_vruntime;
	if (locked)
		raw_spin_unlock_irqrestore(&rq->lock, flags);
	SEQ_printf_at_AEE(m, "  .%-30s: %lld.%06ld\n", "MIN_vruntime",
			SPLIT_NS(MIN_vruntime));
	SEQ_printf_at_AEE(m, "  .%-30s: %lld.%06ld\n", "min_vruntime",
			SPLIT_NS(min_vruntime));
	SEQ_printf_at_AEE(m, "  .%-30s: %lld.%06ld\n", "max_vruntime",
			SPLIT_NS(max_vruntime));
	spread = max_vruntime - MIN_vruntime;
	/*
	 * SEQ_printf_at_AEE(m, "  .%-30s: %Ld.%06ld\n", "spread",
	 *		SPLIT_NS(spread));
	 */
	spread0 = min_vruntime - rq0_min_vruntime;
	/*
	 * SEQ_printf_at_AEE(m, "  .%-30s: %Ld.%06ld\n", "spread0",
	 *		SPLIT_NS(spread0));
	 * SEQ_printf_at_AEE(m, "  .%-30s: %d\n", "nr_spread_over",
	 *		cfs_rq->nr_spread_over);
	 */
	SEQ_printf_at_AEE(m, "  .%-30s: %d\n", "nr_running", cfs_rq->nr_running);
	SEQ_printf_at_AEE(m, "  .%-30s: %ld\n", "load", cfs_rq->load.weight);
#ifdef CONFIG_SMP
	SEQ_printf_at_AEE(m, "  .%-30s: %lu\n", "load_avg",
			cfs_rq->avg.load_avg);
	SEQ_printf_at_AEE(m, "  .%-30s: %lu\n", "runnable_load_avg",
			cfs_rq->runnable_load_avg);
	SEQ_printf_at_AEE(m, "  .%-30s: %lu\n", "util_avg",
			cfs_rq->avg.util_avg);
	SEQ_printf_at_AEE(m, "  .%-30s: %ld\n", "removed_load_avg",
			atomic_long_read(&cfs_rq->removed_load_avg));
	SEQ_printf_at_AEE(m, "  .%-30s: %ld\n", "removed_util_avg",
			atomic_long_read(&cfs_rq->removed_util_avg));
#ifdef CONFIG_FAIR_GROUP_SCHED
	SEQ_printf_at_AEE(m, "  .%-30s: %lu\n", "tg_load_avg_contrib",
			cfs_rq->tg_load_avg_contrib);
	SEQ_printf_at_AEE(m, "  .%-30s: %ld\n", "tg_load_avg",
			atomic_long_read(&cfs_rq->tg->load_avg));
#endif
#endif
#ifdef CONFIG_CFS_BANDWIDTH
	SEQ_printf_at_AEE(m, "  .%-30s: %d\n", "throttled",
			cfs_rq->throttled);
	SEQ_printf_at_AEE(m, "  .%-30s: %d\n", "throttle_count",
			cfs_rq->throttle_count);
#endif

#ifdef CONFIG_FAIR_GROUP_SCHED
	print_cfs_group_stats_at_AEE(m, cpu, cfs_rq->tg);
#endif
}

#define for_each_leaf_cfs_rq(rq, cfs_rq) \
	list_for_each_entry_rcu(cfs_rq, &rq->leaf_cfs_rq_list, leaf_cfs_rq_list)


void print_cfs_stats_at_AEE(struct seq_file *m, int cpu)
{
	struct cfs_rq *cfs_rq;

	rcu_read_lock();
	cfs_rq = &cpu_rq(cpu)->cfs;
	/*sched: only output / cgroup schedule info*/
	print_cfs_rq_at_AEE(m, cpu, cfs_rq);
	rcu_read_unlock();
}

void print_rt_rq_at_AEE(struct seq_file *m, int cpu, struct rt_rq *rt_rq)
{
#ifdef CONFIG_RT_GROUP_SCHED
	int cpu_rq_throttle = rq_cpu(rt_rq->rq);
	SEQ_printf_at_AEE(m, "\nrt_rq[%d]:%s\n", cpu, task_group_path(rt_rq->tg));
#else
	SEQ_printf_at_AEE(m, "\nrt_rq[%d]:\n", cpu);
#endif

#define P(x) \
	SEQ_printf_at_AEE(m, "  .%-30s: %lld\n", #x, (long long)(rt_rq->x))
#define PN(x) \
	SEQ_printf_at_AEE(m, "  .%-30s: %lld.%06ld\n", #x, SPLIT_NS(rt_rq->x))

	P(rt_nr_running);
	P(rt_throttled);

	SEQ_printf_at_AEE(m, "  exec_task[%d:%s], prio=%d\n",
			per_cpu(exec_task, cpu).pid,
			per_cpu(exec_task, cpu).comm,
			per_cpu(exec_task, cpu).prio);
#ifdef CONFIG_RT_GROUP_SCHED
	SEQ_printf_at_AEE(m, "  .rt_throttling_start   : [%llu]\n", per_cpu(rt_throttling_start, cpu_rq_throttle));
#endif

	PN(rt_time);
	PN(rt_runtime);

#undef PN
#undef P
}


#ifdef CONFIG_RT_GROUP_SCHED
typedef struct task_group *rt_rq_iter_t;

static inline struct task_group *next_task_group(struct task_group *tg)
{
	do {
		tg = list_entry_rcu(tg->list.next,
			typeof(struct task_group), list);
	} while (&tg->list != &task_groups && task_group_is_autogroup(tg));

	if (&tg->list == &task_groups)
		tg = NULL;

	return tg;
}

#define for_each_rt_rq(rt_rq, iter, rq)					\
	for (iter = container_of(&task_groups, typeof(*iter), list);	\
		(iter = next_task_group(iter)) &&			\
		(rt_rq = iter->rt_rq[cpu_of(rq)]);)

#else /* !CONFIG_RT_GROUP_SCHED */

typedef struct rt_rq *rt_rq_iter_t;

#define for_each_rt_rq(rt_rq, iter, rq) \
	for ((void) iter, rt_rq = &rq->rt; rt_rq; rt_rq = NULL)

#endif

void print_rt_stats_at_AEE(struct seq_file *m, int cpu)
{
	struct rt_rq *rt_rq;

	rt_rq = &cpu_rq(cpu)->rt;

	rcu_read_lock();
	/*sched: only output / cgroup schedule info*/
	print_rt_rq_at_AEE(m, cpu, rt_rq);
	rcu_read_unlock();
}

void print_dl_rq_at_AEE(struct seq_file *m, int cpu, struct dl_rq *dl_rq)
{
	SEQ_printf_at_AEE(m, "\ndl_rq[%d]:\n", cpu);
	SEQ_printf_at_AEE(m, "  .%-30s: %ld\n", "dl_nr_running", dl_rq->dl_nr_running);
}

void print_dl_stats_at_AEE(struct seq_file *m, int cpu)
{
	print_dl_rq_at_AEE(m, cpu, &cpu_rq(cpu)->dl);
}

static void print_cpu_at_AEE(struct seq_file *m, int cpu)
{
	struct rq *rq = cpu_rq(cpu);
	unsigned long flags;
	int locked;

#ifdef CONFIG_X86
	{
		unsigned int freq = cpu_khz ? : 1;

		SEQ_printf_at_AEE(m, "cpu#%d, %u.%03u MHz\n",
			   cpu, freq / 1000, (freq % 1000));
	}
#else
	/* sched: add cpu info */
	SEQ_printf_at_AEE(m, "cpu#%d: %s\n", cpu, cpu_is_offline(cpu)?"Offline":"Online");
#endif

#define P(x)								\
do {									\
	if (sizeof(rq->x) == 4)						\
		SEQ_printf_at_AEE(m, "  .%-30s: %ld\n", #x, (long)(rq->x));	\
	else								\
		SEQ_printf_at_AEE(m, "  .%-30s: %lld\n", #x, (long long)(rq->x));\
} while (0)

#define PN(x) \
	SEQ_printf_at_AEE(m, "  .%-30s: %lld.%06ld\n", #x, SPLIT_NS(rq->x))

	P(nr_running);
	SEQ_printf_at_AEE(m, "  .%-30s: %lu\n", "load",
		   rq->load.weight);
	/*P(nr_switches);*/
	P(nr_load_updates);
	P(nr_uninterruptible);
	PN(next_balance);
	SEQ_printf_at_AEE(m, "  .%-30s: %ld\n", "curr->pid", (long)(task_pid_nr(rq->curr)));
	PN(clock);
	PN(clock_task);
	SEQ_printf_at_AEE(m, "  .%-30s: %ld %ld %ld %ld %ld\n", "cpu_load",
			(long)(rq->cpu_load[0]),
			(long)(rq->cpu_load[1]),
			(long)(rq->cpu_load[2]),
			(long)(rq->cpu_load[3]),
			(long)(rq->cpu_load[4]));
	/*
	 * P(cpu_load[0]);
	 * P(cpu_load[1]);
	 * P(cpu_load[2]);
	 * P(cpu_load[3]);
	 * P(cpu_load[4]);
	 */
#undef P
#undef PN

#ifdef CONFIG_SCHEDSTATS
#define P(n) SEQ_printf_at_AEE(m, "  .%-30s: %d\n", #n, rq->n)
#define P64(n) SEQ_printf_at_AEE(m, "  .%-30s: %lld\n", #n, rq->n)
	/*
	 * P(yld_count);
	 * P(sched_count);
	 * P(sched_goidle);
	 */
#ifdef CONFIG_SMP
	P64(avg_idle);
	P64(max_idle_balance_cost);
#endif
	/*
	 * P(ttwu_count);
	 * P(ttwu_local);
	 */
#undef P
#undef P64
#endif
	/*spin_lock_irqsave_lock_irqsave(&sched_debug_lock, flags);*/
	locked = spin_trylock_n_irqsave(&sched_debug_lock, &flags, m, "print_cpu_at_AEE");
	print_cfs_stats_at_AEE(m, cpu);
	print_rt_stats_at_AEE(m, cpu);
	print_dl_stats_at_AEE(m, cpu);

	rcu_read_lock();
	print_rq_at_AEE(m, rq, cpu);
	SEQ_printf_at_AEE(m, "============================================\n");
	rcu_read_unlock();
	/*spin_unlock_irqrestore(&sched_debug_lock, flags);*/
	if (locked)
		spin_unlock_irqrestore(&sched_debug_lock, flags);
}

static void sched_debug_header_at_AEE(struct seq_file *m)
{
	u64 sched_clk, cpu_clk;
	unsigned long flags;

#ifdef TEST_SCHED_DEBUG_ENHANCEMENT
	struct rq *rq = cpu_rq(0);
	/* lock_timekeeper(); */
	raw_spin_lock_irq(&rq->lock);
	spin_lock_irqsave(&sched_debug_lock, flags);
	write_lock_irqsave(&tasklist_lock, flags);
#endif

	local_irq_save(flags);
	/*ktime = ktime_to_ns(ktime_get());*/
	sched_clk = sched_clock();
	cpu_clk = local_clock();
	local_irq_restore(flags);

	SEQ_printf_at_AEE(m, "Sched Debug Version: v0.11, %s %.*s\n",
		init_utsname()->release,
		(int)strcspn(init_utsname()->version, " "),
		init_utsname()->version);

#define P(x) \
	SEQ_printf_at_AEE(m, "%-40s: %lld\n", #x, (long long)(x))
#define PN(x) \
	SEQ_printf_at_AEE(m, "%-40s: %lld.%06ld\n", #x, SPLIT_NS(x))
	/*PN(ktime);*/
	PN(sched_clk);
	PN(cpu_clk);
	P(jiffies);
#ifdef CONFIG_HAVE_UNSTABLE_SCHED_CLOCK
	P(sched_clock_stable());
#endif
#undef PN
#undef P

	/*SEQ_printf_at_AEE(m, "\n");*/
	SEQ_printf_at_AEE(m, "sysctl_sched\n");

#define P(x) \
	SEQ_printf_at_AEE(m, "  .%-40s: %lld\n", #x, (long long)(x))
#define PN(x) \
	SEQ_printf_at_AEE(m, "  .%-40s: %lld.%06ld\n", #x, SPLIT_NS(x))
	PN(sysctl_sched_latency);
	PN(sysctl_sched_min_granularity);
	PN(sysctl_sched_wakeup_granularity);
	P(sysctl_sched_child_runs_first);
	P(sysctl_sched_features);
#undef PN
#undef P

	SEQ_printf_at_AEE(m, "  .%-40s: %d (%s)\n",
		"sysctl_sched_tunable_scaling",
		sysctl_sched_tunable_scaling,
		sched_tunable_scaling_names[sysctl_sched_tunable_scaling]);
	SEQ_printf_at_AEE(m, "\n");
}

void sysrq_sched_debug_show_at_AEE(void)
{
	int cpu;
	unsigned long flags;
	int locked;

	sched_debug_header_at_AEE(NULL);
	/* read_lock_irqsave(&tasklist_lock, flags); */
	locked = read_trylock_n_irqsave(&tasklist_lock, &flags, NULL, "sched_debug_show_at_AEE");

	/* for_each_online_cpu(cpu) */
	for_each_possible_cpu(cpu) {
		print_cpu_at_AEE(NULL, cpu);
	}
	if (locked)
		read_unlock_irqrestore(&tasklist_lock, flags);
#ifdef CONFIG_MTK_RT_THROTTLE_MON
	/* sched:rt throttle monitor */
	mt_rt_mon_print_task_from_buffer();
#endif
}
