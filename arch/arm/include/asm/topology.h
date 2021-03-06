/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM_TOPOLOGY_H
#define _ASM_ARM_TOPOLOGY_H

#ifdef CONFIG_ARM_CPU_TOPOLOGY

#include <linux/cpumask.h>

struct cputopo_arm {
	int thread_id;
	int core_id;
	int socket_id;
	unsigned int partno;
	cpumask_t thread_sibling;
	cpumask_t core_sibling;
};

extern struct cputopo_arm cpu_topology[NR_CPUS];
extern unsigned long arch_get_max_cpu_capacity(int);
extern unsigned long arch_get_cur_cpu_capacity(int);
extern unsigned long cpufreq_scale_max_freq_capacity(int cpu);

#define topology_physical_package_id(cpu)	(cpu_topology[cpu].socket_id)
#define topology_core_id(cpu)		(cpu_topology[cpu].core_id)
#define topology_core_cpumask(cpu)	(&cpu_topology[cpu].core_sibling)
#define topology_sibling_cpumask(cpu)	(&cpu_topology[cpu].thread_sibling)
#define topology_max_cpu_capacity(cpu) (arch_get_max_cpu_capacity(cpu))
#define topology_cur_cpu_capacity(cpu) (arch_get_cur_cpu_capacity(cpu))

void init_cpu_topology(void);
void store_cpu_topology(unsigned int cpuid);
const struct cpumask *cpu_coregroup_mask(int cpu);

#include <linux/arch_topology.h>

/* Replace task scheduler's default frequency-invariant accounting */
#define arch_scale_freq_capacity topology_get_freq_scale

/* Replace task scheduler's default max-frequency-invariant accounting */
#define arch_scale_max_freq_capacity topology_get_max_freq_scale

/* Replace task scheduler's default cpu-invariant accounting */
#define arch_scale_cpu_capacity topology_get_cpu_scale

/* Enable topology flag updates */
#define arch_update_cpu_topology topology_update_cpu_topology

#else

static inline void init_cpu_topology(void) { }
static inline void store_cpu_topology(unsigned int cpuid) { }

static inline int arch_cpu_is_big(unsigned int cpu) { return 0; }
static inline int arch_cpu_is_little(unsigned int cpu) { return 1; }
static inline int arch_is_multi_cluster(void) { return 0; }
static inline int arch_is_smp(void) { return 1; }
static inline int arch_get_nr_clusters(void) { return 1; }
static inline int arch_get_cluster_id(unsigned int cpu) { return 0; }
static inline void arch_get_cluster_cpus(struct cpumask *cpus, int cluster_id)
{
	cpumask_clear(cpus);
	if (cluster_id == 0) {
		unsigned int cpu;

		for_each_possible_cpu(cpu)
			cpumask_set_cpu(cpu, cpus);
	}
}
static inline int arch_better_capacity(unsigned int cpu) { return 0; }

#endif

#ifdef CONFIG_MTK_CPU_TOPOLOGY
void arch_build_cpu_topology_domain(void);
#endif


#ifdef CONFIG_MTK_SCHED_EAS_POWER_SUPPORT
extern inline
int mtk_idle_power(int idle_state, int cid, void *argu, int);

extern inline
int mtk_busy_power(int cpu, void *argu, int);
#endif


#include <asm-generic/topology.h>

#endif /* _ASM_ARM_TOPOLOGY_H */
