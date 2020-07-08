#
# Copyright 2017-2020 VMware, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
#

###
### @file    cbclone_low.S
###
### @brief   Low level clone syscall family (clone,fork,vfork) interceptors
###          Need asm due to the nature of the clone() invocation
###          These function will call the C wrapper to do the proxy work
###
### @copyright (c) 2016 Carbon Black, Inc. All rights reserved.
###

#undef CONFIG_AS_CFI
#include <asm/dwarf2.h>
#include <asm/calling.h>
#include <asm/unistd.h>
#include "syscall_stub.h"

#define PRE_OK(call)			call##_pre_ok
#define LOCAL_RET_ADDR(call)	call##_loc_ret_addr
#define ORIG_RET_PTR(call)		call##_orig_return

#
#	When interpcepting the clone calls, we must ensure that the stack is not modified
#	during the interception as these calls will not work if the layout is not as expected.
#	This presents a problem -- we have no local storage (e.g., to save anything across calls).
#	Additionally, the pre-call must return here rather then to the original caller, again
#	requiring local store for the original return address.
#	We can't push the new return address, that would disrupt the stack layout, so we patch
#	the stack in place, and need to temporarily store the return address somewhere.
#	The solution in the original Cb code (by Robert) was to save it in a static variable
#	(at the bottom of this file). I am not sure that will always work as there are two places
#	from where this call can be made (in entry_64.S).
#	But not having a better solution, I am reluctantly keeping it.
#
#	Replicating the identical procedure does not look very clean but it eliminates some of the
#	parametrization that would be have been required with a common procedure (we do the minimum
#	processing required at this level, and then call a common upper half in cbclone.c).
#	Note that these are x86 register-only arg passing calls and the callee is allowed to modify
#	the arg registers, so the question is how to preserve the args between the pre-call
#	and the post-call.  The two pre and post parameters passed up (id, flags) are handled
#	differently. The id is implied by the [static] handler, and thus does not have to be saved.
#	The flags are retrieved from the stack where the original caller saved the frame (SYSCALL_FLAGS_OFF).
#

#define _SYSCALL_NO(call)       __NR_##call
#define SYSCALL_NO(call)        _SYSCALL_NO(call)
#define SYSCALL_FLAGS_OFF       (ARG_SKIP+8+RDI)

.text
.global CBSYSSTUB_NAME(clone)
CBSYSSTUB_NAME(clone):
	SAVE_ALL
	movq $SYSCALL_NO(clone),%rdi      # syscall NR (in the syscall table)
	movq SYSCALL_FLAGS_OFF(%rsp),%rsi # syscall flags
	callq _cb_pre_clone               # call the C "pre" wrapper
	testq %rax,%rax
	jz  PRE_OK(clone)
	# "pre" says NO
	RESTORE_ALL
	movq $-1,%rax
	retq
PRE_OK(clone):
	RESTORE_ALL
	# fudge the return address forcing the callee to return here
	pushfq                          # store old ret address for later
	pushq %rax
	movq 16(%rsp), %rax
	movq %rax,ORIG_RET_PTR(clone)   # save the old address
	leaq LOCAL_RET_ADDR(clone),%rax
	movq %rax,16(%rsp)              # replace it with a local label
	popq %rax
	popfq
	jmpq *(ORIG_SYSCALL_PTR(clone))	# call the original syscall table entry
LOCAL_RET_ADDR(clone):
	pushq ORIG_RET_PTR(clone)       # put back our caller's return address
	# make the post call
	SAVE_ALL
	movq $SYSCALL_NO(clone),%rdi
	movq SYSCALL_FLAGS_OFF(%rsp),%rsi
	movq %rax,%rdx                  # child pid returned by the original syscall above
	callq _cb_post_clone            # call the C "post" wrapper
	RESTORE_ALL
	retq

.global CBSYSSTUB_NAME(fork)
CBSYSSTUB_NAME(fork):
	SAVE_ALL
	movq $SYSCALL_NO(fork),%rdi       # syscall NR (in the syscall table)
	movq SYSCALL_FLAGS_OFF(%rsp),%rsi # syscall flags
	callq _cb_pre_clone               # call the C "pre" wrapper
	testq %rax,%rax
	jz  PRE_OK(fork)
	# "pre" says NO
	RESTORE_ALL
	movq $-1,%rax
	retq
PRE_OK(fork):
	RESTORE_ALL
	# fudge the return address forcing the callee to return here
	pushfq                          # store old ret address for later
	pushq %rax
	movq 16(%rsp), %rax
	movq %rax,ORIG_RET_PTR(fork)    # save the old address
	leaq LOCAL_RET_ADDR(fork),%rax
	movq %rax,16(%rsp)              # replace it with a local label
	popq %rax
	popfq
	jmpq *(ORIG_SYSCALL_PTR(fork))	# call the original syscall table entry
LOCAL_RET_ADDR(fork):
	pushq ORIG_RET_PTR(fork)        # put back our caller's return address
	# make the post call
	SAVE_ALL
	movq $SYSCALL_NO(fork),%rdi
	movq SYSCALL_FLAGS_OFF(%rsp),%rsi
	movq %rax,%rdx                  # child pid returned by the original syscall above
	callq _cb_post_clone            # call the C "post" wrapper
	RESTORE_ALL
	retq

.global CBSYSSTUB_NAME(vfork)
CBSYSSTUB_NAME(vfork):
	SAVE_ALL
	movq $SYSCALL_NO(vfork),%rdi      # syscall NR (in the syscall table)
	movq SYSCALL_FLAGS_OFF(%rsp),%rsi # syscall flags
	callq _cb_pre_clone               # call the C "pre" wrapper
	testq %rax,%rax
	jz  PRE_OK(vfork)
	# "pre" says NO
	RESTORE_ALL
	movq $-1,%rax
	retq
PRE_OK(vfork):
	RESTORE_ALL
	# fudge the return address forcing the callee to return here
	pushfq                          # store old ret address for later
	pushq %rax
	movq 16(%rsp), %rax
	movq %rax,ORIG_RET_PTR(vfork)   # save the old address
	leaq LOCAL_RET_ADDR(vfork),%rax
	movq %rax,16(%rsp)              # replace it with a local label
	popq %rax
	popfq
	jmpq *(ORIG_SYSCALL_PTR(vfork))	# call the original syscall table entry
LOCAL_RET_ADDR(vfork):
	pushq ORIG_RET_PTR(vfork)       # put back our caller's return address
	# make the post call
	SAVE_ALL
	movq $SYSCALL_NO(vfork),%rdi
	movq SYSCALL_FLAGS_OFF(%rsp),%rsi
	movq %rax,%rdx                  # child pid returned by the original syscall above
	callq _cb_post_clone            # call the C "post" wrapper
	RESTORE_ALL
	retq

.data
.global ORIG_SYSCALL_PTR(clone)
ORIG_SYSCALL_PTR(clone):             .quad 0x0
.global ORIG_SYSCALL_PTR(fork)
ORIG_SYSCALL_PTR(fork):              .quad 0x0
.global ORIG_SYSCALL_PTR(vfork)
ORIG_SYSCALL_PTR(vfork):             .quad 0x0
# temporary store for the original return address (static! -- see the comments at the top)
ORIG_RET_PTR(clone):                 .quad 0x0
ORIG_RET_PTR(fork):                  .quad 0x0
ORIG_RET_PTR(vfork):                 .quad 0x0
