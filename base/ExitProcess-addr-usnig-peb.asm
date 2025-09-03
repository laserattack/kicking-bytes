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
    
    ; Получаем адрес PE-заголовка
    mov eax, [ebx+0x3C]   ; e_lfanew
    add eax, ebx          ; адрес PE-заголовка
    
    ; Получаем адрес таблицы экспорта
    mov eax, [eax+0x78]   ; RVA таблицы экспорта
    add eax, ebx          ; VA таблицы экспорта
    
    ; Сохраняем важные указатели в регистрах
    mov edx, eax          ; EDX = export table
    
    ; Получаем количество имен функций
    mov ecx, [eax+0x18]   ; NumberOfNames
    
    ; Получаем RVA таблицы имен
    mov eax, [eax+0x20]   ; AddressOfNames RVA
    add eax, ebx          ; VA таблицы имен
    mov esi, eax          ; ESI = таблица имен
    
    ; Получаем RVA таблицы адресов функций
    mov eax, [edx+0x1C]   ; AddressOfFunctions RVA
    add eax, ebx          ; VA таблицы адресов функций
    mov edi, eax          ; EDI = таблица адресов функций
    
    ; Получаем RVA таблицы ординалов
    mov eax, [edx+0x24]   ; AddressOfNameOrdinals RVA
    add eax, ebx          ; VA таблицы ординалов
    mov ebp, eax          ; EBP = таблица ординалов
    
    ; Цикл поиска функции
    xor edx, edx          ; EDX будет хранить индекс
    
.search_loop:
    ; Получаем RVA имени функции
    mov eax, [esi]
    add eax, ebx          ; VA имени функции
    
    ; Сравниваем с искомым именем
    push esi
    push ecx
    push edx
    push eax
    push target_function
    call [strcmp]
    add esp, 8
    pop edx
    pop ecx
    pop esi
    
    ; Если нашли функцию
    test eax, eax
    jz .found_function
    
    ; Следующее имя
    add esi, 4
    inc edx
    loop .search_loop
    
    ; Если не нашли функцию
    push not_found_msg
    call [printf]
    add esp, 4
    jmp .exit
    
.found_function:
    ; Получаем ординал функции
    movzx eax, word [ebp + edx * 2] ; получаем ординал (16-битное значение)
    
    ; Получаем адрес функции по ординалу
    shl eax, 2            ; умножаем на 4 (размер DWORD)
    add eax, edi          ; адрес в таблице адресов
    mov eax, [eax]        ; RVA функции
    add eax, ebx          ; VA функции (абсолютный адрес)
    
    ; Выводим результат
    push eax
    push target_function
    push found_msg
    call [printf]
    add esp, 12
    
.exit:
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
    strcmp dd RVA _strcmp
    dd 0

kernel32 db 'KERNEL32.DLL', 0
msvcrt db 'MSVCRT.DLL', 0

_ExitProcess dw 0
db 'ExitProcess', 0

_printf dw 0
db 'printf', 0

_strcmp dw 0
db 'strcmp', 0

section '.data' data readable writeable
    target_function db 'ExitProcess', 0
    found_msg db 'Function %s found at address: 0x%08X', 10, 0
    not_found_msg db 'Function not found!', 10, 0
