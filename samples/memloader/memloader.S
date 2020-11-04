.section .data
.globl blob_start
.globl blob_end

blob_start:
.incbin MODULE_FILE
blob_end: