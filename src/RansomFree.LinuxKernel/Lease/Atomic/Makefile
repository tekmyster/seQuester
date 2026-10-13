obj-m += sq_actor_lease.o
ccflags-y += -Werror
ifeq ($(SQ_KERNEL61_ATOMIC_ONLY),1)
ccflags-y += -DSQ_KERNEL61_ATOMIC_ONLY
endif
ifeq ($(SQ_QUALIFICATION),1)
ccflags-y += -DSQ_LEASE_QUALIFICATION
endif
