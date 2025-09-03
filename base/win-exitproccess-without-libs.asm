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

search_loop:
    ; Получаем RVA имени функции
    mov eax, [esi]
    add eax, ebx          ; VA имени функции
    
    ; Сравниваем с искомым именем (встроенное сравнение строк)
    push esi
    push edi
    push ecx
    push edx
    
    mov esi, eax          ; ESI = текущее имя функции
    mov edi, target_function ; EDI = искомое имя
    
compare_loop:
    mov al, [esi]
    mov cl, [edi]
    cmp al, cl
    jne not_equal
    test al, al
    jz equal
    inc esi
    inc edi
    jmp compare_loop

equal:
    xor eax, eax
    jmp compare_done

not_equal:
    mov eax, 1

compare_done:
    pop edx
    pop ecx
    pop edi
    pop esi
    
    ; Если нашли функцию (строки равны)
    test eax, eax
    jz found_function
    
    ; Следующее имя
    add esi, 4
    inc edx
    loop search_loop

found_function:
    ; Получаем ординал функции
    movzx eax, word [ebp + edx * 2] ; получаем ординал (16-битное значение)
    
    ; Получаем адрес функции по ординалу
    shl eax, 2            ; умножаем на 4 (размер DWORD)
    add eax, edi          ; адрес в таблице адресов
    mov eax, [eax]        ; RVA функции
    add eax, ebx          ; VA функции (абсолютный адрес)
    
    ; Вызываем ExitProcess с кодом равным ее адресу
    push eax
    call eax              ; вызываем найденную функцию

section '.data' data readable writeable
    target_function db 'ExitProcess', 0
