; vim: set filetype=fasm :

format PE console
entry start

section '.text' code readable executable

start:
    ; Получаем PEB
    mov eax, [fs:0x30]    ; PEB
    
    ; Получаем PEB_LDR_DATA
    mov eax, [eax + 0x0C] ; PEB->Ldr
    
    ; Получаем список загруженных модулей (InMemoryOrderModuleList)
    mov eax, [eax + 0x14] ; PEB_LDR_DATA->InMemoryOrderModuleList
    
    ; Первый модуль - сама программа, второй - обычно ntdll.dll, третий - kernel32.dll
    mov eax, [eax]        ; Следующий модуль (ntdll.dll)
    mov eax, [eax]        ; Следующий модуль (kernel32.dll)
    
    ; Получаем базовый адрес модуля (DllBase)
    mov ebx, [eax + 0x10] ; LDR_DATA_TABLE_ENTRY->DllBase
    
    ; Выводим адрес kernel32.dll
    push ebx
    push kernel32_msg
    call [printf]
    
    ; Получаем адрес PE-заголовка
    mov eax, [ebx+0x3C]   ; e_lfanew
    add eax, ebx          ; адрес PE-заголовка
    
    ; Получаем адрес таблицы экспорта
    mov eax, [eax+0x78]   ; RVA таблицы экспорта
    add eax, ebx          ; VA таблицы экспорта
    
    ; Выводим адрес таблицы экспорта
    push eax
    push export_table_msg
    call [printf]
    
    ; Выход
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
    kernel32_msg db 'kernel32.dll base address: 0x%08X', 10, 0
    export_table_msg db 'Export table address: 0x%08X', 10, 0
