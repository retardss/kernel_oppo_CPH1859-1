# SPDX-License-Identifier: GPL-2.0
obj-$(CONFIG_PM_DEVFREQ)	+= devfreq.o
obj-$(CONFIG_PM_DEVFREQ_EVENT)	+= devfreq-event.o
obj-$(CONFIG_DEVFREQ_GOV_SIMPLE_ONDEMAND)	+= governor_simpleondemand.o
obj-$(CONFIG_DEVFREQ_GOV_PERFORMANCE)	+= governor_performance.o
obj-$(CONFIG_DEVFREQ_GOV_POWERSAVE)	+= governor_powersave.o
obj-$(CONFIG_DEVFREQ_GOV_USERSPACE)	+= governor_userspace.o
obj-$(CONFIG_DEVFREQ_GOV_PASSIVE)	+= governor_passive.o
#obj-$(CONFIG_DEVFREQ_GOV_CPUFREQ)	+= governor_cpufreq.o
obj-$(CONFIG_DEVFREQ_GOV_QCOM_ADRENO_TZ) += governor_msm_adreno_tz.o
obj-$(CONFIG_DEVFREQ_GOV_QCOM_GPUBW_MON) += governor_bw_vbif.o
obj-$(CONFIG_DEVFREQ_GOV_QCOM_GPUBW_MON) += governor_gpubw_mon.o
obj-$(CONFIG_QCOM_BIMC_BWMON)		+= bimc-bwmon.o
obj-$(CONFIG_ARM_MEMLAT_MON)		+= arm-memlat-mon.o
obj-$(CONFIG_QCOMCCI_HWMON)		+= msmcci-hwmon.o
obj-$(CONFIG_QCOM_M4M_HWMON)		+= m4m-hwmon.o
obj-$(CONFIG_DEVFREQ_GOV_QCOM_BW_HWMON)	+= governor_bw_hwmon.o
obj-$(CONFIG_DEVFREQ_GOV_QCOM_CACHE_HWMON)	+= governor_cache_hwmon.o
obj-$(CONFIG_DEVFREQ_GOV_SPDM_HYP)	+= governor_spdm_bw_hyp.o
obj-$(CONFIG_DEVFREQ_GOV_MEMLAT)       += governor_memlat.o
obj-$(CONFIG_DEVFREQ_GOV_CDSPL3)	+= governor_cdsp_l3.o

# DEVFREQ Drivers
obj-$(CONFIG_ARM_EXYNOS_BUS_DEVFREQ)	+= exynos-bus.o
obj-$(CONFIG_ARM_RK3399_DMC_DEVFREQ)	+= rk3399_dmc.o
obj-$(CONFIG_ARM_TEGRA_DEVFREQ)		+= tegra-devfreq.o
obj-$(CONFIG_QCOM_DEVFREQ_DEVBW)		+= devfreq_devbw.o
obj-$(CONFIG_DEVFREQ_SIMPLE_DEV)	+= devfreq_simple_dev.o
obj-$(CONFIG_DEVFREQ_SPDM)		+= devfreq_spdm.o devfreq_spdm_debugfs.o

ccflags-y += -I$(srctree)/drivers/misc/mediatek/base/power/include/
ccflags-y += -I$(srctree)/drivers/misc/mediatek/include/
ccflags-y += -I$(srctree)/drivers/misc/mediatek/include/mt-plat/$(MTK_PLATFORM)/include/
ccflags-y += -I$(srctree)/drivers/watchdog/mediatek/include/
ccflags-y += -I$(srctree)/drivers/misc/mediatek/dramc/$(MTK_PLATFORM)/
ccflags-y += -I$(srctree)/drivers/misc/mediatek/sspm/
ccflags-y += -I$(srctree)/drivers/misc/mediatek/sspm/$(MTK_PLATFORM)/

ifeq ($(CONFIG_MTK_QOS_SUPPORT), y)
#obj-$(CONFIG_MACH_MT6775)		+= helio-dvfsrc.o helio-dvfsrc-sysfs.o
obj-$(CONFIG_MACH_MT6771)		+= helio-dvfsrc.o helio-dvfsrc-sysfs.o

#obj-$(CONFIG_MACH_MT6775)		+= helio-dvfsrc-mt6775.o
obj-$(CONFIG_MACH_MT6771)		+= helio-dvfsrc-mt6771.o
endif

obj-$(CONFIG_MACH_MT6775)		+= helio-dvfsrc-opp-mt6775.o
obj-$(CONFIG_MACH_MT6771)		+= helio-dvfsrc-opp-mt6771.o

# DEVFREQ Event Drivers
obj-$(CONFIG_PM_DEVFREQ_EVENT)		+= event/
