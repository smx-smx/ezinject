#!/bin/sh
#
# Copyright (C) 2025 Stefano Moioli <smxdev4@gmail.com>
# This software is provided 'as-is', without any express or implied warranty.
# In no event will the authors be held liable for any damages arising from
# the use of this software.
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it
# freely, subject to the following restrictions:
#  1. The origin of this software must not be misrepresented; you must not
#     claim that you wrote the original software. If you use this software
#     in a product, an acknowledgment in the product documentation would be
#     appreciated but is not required.
#  2. Altered source versions must be plainly marked as such, and must not
#     be misrepresented as being the original software.
#  3. This notice may not be removed or altered from any source distribution.
#
# Shell port of hppa_patch_calls.php
#
# On HPPA, the ABI mandates function descriptors which require GOT
# references for indirect calls. With -mfast-indirect-calls, GCC emits
# kernel-mode BLE instructions using space registers (sr4).
# This script replaces those with an equivalent usermode sequence
# that dereferences a manually-constructed function descriptor.
#
# The descriptor layout in ezinject is:
#   struct { void *fptr; void *got; void *self; }
# where self points to fptr in the remote process.
#
# Usage: hppa_patch_calls.sh <input.s> <output.s>

INPUT="$1"
OUTPUT="$2"

if [ -z "$INPUT" ] || [ -z "$OUTPUT" ]; then
	echo "Usage: $0 <input.s> <output.s>" >&2
	exit 1
fi

# The usermode call sequence replacing 'ble 0(%sr4,%r22)'
patch=';  get current PC
; rp: after delay slot (stored in r31 to emulate ble)
b,l 0, %r31
; clear privilege level from the pointer
depwi 0,31,2,%r31

; <-- rp (r31)
ldo 20(%r31), %r31

; <-- rp+4
; first, dereference the descriptor pointer into r19
ldw 0(%r22), %r19

; <-- rp+8
copy %r31, %rp

; <-- rp+12
; call descr.fptr
bv 0(%r19)
; load descr.got within the delay slot
;<-- rp+16
ldw 4(%r22), %r19
;<-- rp+20'

awk -v old='ble 0(%sr4,%r22)' -v new="$patch" '
{
	while (pos = index($0, old)) {
		$0 = substr($0, 1, pos-1) new substr($0, pos+length(old))
	}
	print
}' "$INPUT" > "$OUTPUT"
