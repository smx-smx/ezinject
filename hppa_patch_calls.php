<?php
/*
 * Copyright (C) 2025 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */


$input_file = $argv[1];
$output_file = $argv[2];

/**
 * on HPPA, there doesn't seem to be a way to emit indirect calls using registers.
 * the ABI mandates that we should always use function descriptors, which require
 * global data (GOT references).
 * 
 * there is an exception: when we build kernel mode code, we can 
 * use the compiler flag `mfast-indirect-calls` to skip the GOT, and emit
 * a register-based BLE instead.
 * 
 * however, since BLE is a kernel-mode function (using space registers),
 * we need to replace it with an equivalent usermode sequence.
 * 
 * let's make our own ABI then!
 * ----------------------------
 * we can define our function descriptors in ezinject with the following struct:
 * 
 * struct {
 *   void (fptr)();
 *   void *got;
 *   void *self; // we set this field to points to `fptr` in the remote process
 * } my_function;
 * 
 * we then force `self` to be used as the address of the call, instead of `fptr`,
 * with the macro `CALL_FPTR`.
 * 
 * By doing this, we end up with the *ADDRESS* of the function pointer in %r22 (aka &fptr),
 * rather than the function address itself.
 * 
 * we can now dereference 0(%r22) to get `fptr`,
 * and 4(%r22) to get `got`
 */
$patch=<<<EOS
;  get current PC
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
;<-- rp+20
EOS;

$patched_data = preg_replace(
    '/' . preg_quote('ble 0(%sr4,%r22)') . '/',
    $patch,
    file_get_contents($input_file),
);
file_put_contents($output_file, $patched_data);
