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
    mov [kernel32_base], ebx
    
    ; Получаем адрес PE-заголовка
    mov eax, [ebx+0x3C]   ; e_lfanew
    add eax, ebx          ; адрес PE-заголовка
    
    ; Получаем адрес таблицы экспорта
    mov eax, [eax+0x78]   ; RVA таблицы экспорта
    add eax, ebx          ; VA таблицы экспорта
    mov [export_table], eax
    
    ; Сохраняем важные указатели
    mov edx, eax          ; EDX = export table
    
    ; Получаем количество имен функций
    mov ecx, [eax+0x18]   ; NumberOfNames
    mov [num_names], ecx
    
    ; Получаем RVA таблицы имен
    mov eax, [eax+0x20]   ; AddressOfNames RVA
    add eax, ebx          ; VA таблицы имен
    mov [names_table], eax
    
    ; Получаем RVA таблицы адресов функций
    mov eax, [edx+0x1C]   ; AddressOfFunctions RVA
    add eax, ebx          ; VA таблицы адресов функций
    mov [addresses_table], eax
    
    ; Получаем RVA таблицы ординалов
    mov eax, [edx+0x24]   ; AddressOfNameOrdinals RVA
    add eax, ebx          ; VA таблицы ординалов
    mov [ordinals_table], eax
    
    ; Выводим заголовок
    push ecx
    push header_msg
    call [printf]
    add esp, 8
    
    ; Цикл по всем именам функций
    mov esi, [names_table]    ; ESI = таблица имен
    mov edi, [ordinals_table] ; EDI = таблица ординалов
    mov ecx, [num_names]      ; ECX = количество имен
    
.print_loop:
    ; Сохраняем регистры
    push ecx
    push esi
    push edi
    
    ; Получаем RVA имени функции
    mov eax, [esi]
    add eax, ebx          ; VA имени функции
    mov [current_name], eax
    
    ; Получаем ординал функции
    movzx eax, word [edi] ; получаем ординал (16-битное значение)
    
    ; Получаем адрес функции по ординалу
    shl eax, 2            ; умножаем на 4 (размер DWORD)
    add eax, [addresses_table] ; адрес в таблице адресов
    mov eax, [eax]        ; RVA функции
    add eax, ebx          ; VA функции (абсолютный адрес)
    mov [current_address], eax
    
    ; Выводим адрес и имя функции
    push dword [current_name]
    push dword [current_address]
    push function_msg
    call [printf]
    add esp, 12
    
    ; Восстанавливаем регистры
    pop edi
    pop esi
    pop ecx
    
    ; Следующее имя и ординал
    add esi, 4
    add edi, 2
    loop .print_loop
    
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
    kernel32_base dd 0
    export_table dd 0
    names_table dd 0
    addresses_table dd 0
    ordinals_table dd 0
    num_names dd 0
    current_address dd 0
    current_name dd 0
    header_msg db 'Number of named functions: %d', 10, 10, 0
    function_msg db '0x%08X - %s', 10, 0
