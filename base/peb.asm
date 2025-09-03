; vim: set filetype=fasm :

format PE console
entry start

section '.text' code readable executable

start:
    mov eax, [fs:0x30] ; нахождение адреса PEB
   
    ; печать адреса PEB
    push eax
    push message
    call [printf]
   
    ; выход из программы
    push 0
    call [ExitProcess]

section '.idata' import data readable
dd 0, 0, 0, RVA kernel32, RVA kernel32_table
dd 0, 0, 0, RVA msvcrt, RVA msvcrt_table
dd 0, 0, 0, 0, 0

kernel32_table:
    ExitProcess dd RVA _ExitProcess
    dd 0

msvcrt_table:
    printf dd RVA _printf
    dd 0

kernel32 db 'KERNEL32.DLL', 0
msvcrt db 'MSVCRT.DLL', 0

_ExitProcess dw 0
db 'ExitProcess', 0

_printf dw 0
db 'printf', 0

section '.data' data readable writeable
    message db 'PEB address: 0x%08X', 10, 0
