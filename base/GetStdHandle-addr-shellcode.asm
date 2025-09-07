; vim: set filetype=fasm :

format PE console
entry start

section '.text' code readable executable

; ВСПОМОГАТЕЛЬНЫЕ МАКРОСЫ

; ============================================================================
; ============================================================================
; ============================================================================

; Макрос для пуша всех переданных аргументов в стек
macro SUPER_PUSH [args] {
    forward
    push args
}
; Макрос для попа нескольких значений из стека  
macro SUPER_POP [args] {
    forward
    pop args
}
; Получение адреса PEB
macro get_peb_addr output_reg { 
	mov output_reg, [fs:0x30] 
}
; Получение адреса LDR
macro get_ldr_addr peb_addr_reg, output_reg { 
	mov output_reg, [peb_addr_reg + 0x0C]
}
; Получение адреса списка модулей
macro get_modules_list_addr ldr_addr_reg, output_reg {
	mov output_reg, [ldr_addr_reg + 0x14]
}
; Получение адреса N-го модуля в списке модулей
macro get_module_addr modules_list_addr_reg, module_number, output_reg {
    mov output_reg, modules_list_addr_reg
    repeat module_number
        mov output_reg, [output_reg]
    end repeat
}
; Получение базового адреса модуля
macro get_module_base_addr module_addr_reg, output_reg { 
	mov output_reg, [module_addr_reg + 0x10]
}
; Получение адреса PE заголовка модуля
macro get_pe_header_addr module_base_addr_reg, output_reg {
	mov output_reg, [module_base_addr_reg+0x3C]
    add output_reg, module_base_addr_reg
}
; Получение адреса таблицы экспорта модуля
macro get_export_table_addr pe_header_addr_reg, module_base_addr_reg, output_reg {
    mov output_reg, [pe_header_addr_reg+0x78]
	add output_reg, module_base_addr_reg
}
; Получение количества экспортируемых функций
macro get_export_funcs_count export_table_addr_reg, output_reg {
	mov output_reg, [export_table_addr_reg+0x18]
}
; Получение адреса таблицы имен экспортируемых функций модуля
macro get_funs_names_addr module_base_addr_reg, export_table_addr_reg, output_reg {
	mov output_reg, [export_table_addr_reg+0x20]
    add output_reg, module_base_addr_reg
}
; Получение адреса таблицы адресов экспортируемых функций модуля
macro get_funs_addrs_addr module_base_addr_reg, export_table_addr_reg, output_reg {
	mov output_reg, [export_table_addr_reg+0x1C]
    add output_reg, module_base_addr_reg
}
; Получение адреса таблицы ординалов экспортируемых функций модуля
macro get_funs_ordinals_addr module_base_addr_reg, export_table_addr_reg, output_reg {
	mov output_reg, [export_table_addr_reg+0x24]
    add output_reg, module_base_addr_reg
}
; Сравнение строк (аналог strcmp)
macro compare_strings str1_reg, str2_reg, output_reg {
    local compare_loop, not_equal, equal, done
	SUPER_PUSH esi, edi, ecx
    
    mov esi, str1_reg
    mov edi, str2_reg
    
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

not_equal:
    mov output_reg, 1
    jmp done

equal:
    xor output_reg, output_reg

done:
	SUPER_POP ecx, edi, esi
}

; ============================================================================
; ============================================================================
; ============================================================================

; ШЕЛЛКОД
start:

; Поиск адреса ExitProcess
search_ExitProcess:
	; Подготовка к поиску функции
    get_peb_addr eax ; eax <- адрес PEB
	get_ldr_addr eax, eax ; eax <- адрес LDR
    get_modules_list_addr eax, eax ; eax <- адрес списка модулей
    get_module_addr eax, 2, eax ; eax <- адрес модуля
    get_module_base_addr eax, ebx ; ebx <- базовый адрес модуля
	get_pe_header_addr ebx, eax ; eax <- адрес PE-заголовка модуля
	get_export_table_addr eax, ebx, eax ; eax <- адрес таблицы экспорта модуля
    mov edx, eax ; edx <- адрес таблицы экспорта модуля
    get_export_funcs_count eax, ecx ; ecx <- кол-во экспортируемых функций модуля
	get_funs_names_addr ebx, eax, esi ; esi <- адрес таблицы имен экспортируемых функций модуля
    get_funs_addrs_addr ebx, eax, edi ; edi <- адрес таблицы адресов экспортируемых функций модуля
    get_funs_ordinals_addr ebx, eax, ebp ; ebp <- адрес таблицы ординалов экспортируемых функций модуля
	; Поиск ExitProcess
    xor edx, edx ; <- регистр выполняющий функцию счетчика
search_ExitProcess_loop:
    ; Получаем адрес имени функции
    mov eax, [esi]
    add eax, ebx ; eax <- адрес имени функции
    ; Сравниваем с искомым именем
	SUPER_PUSH esi, edi, ecx, edx
    mov edi, esp
    sub edi, 64
    mov dword [edi], 'Exit'
    mov dword [edi+4], 'Proc'
    mov dword [edi+8], 'ess'
    mov byte [edi+11], 0
    compare_strings eax, edi, eax
	SUPER_POP edx, ecx, edi, esi
    ; Если строки равны
    test eax, eax
    jz found_ExitProcess
    ; Иначе след. итерация
    add esi, 4 ; <- переход к адресу след. имени
    inc edx ; <- инкрементирование индекса
    loop search_ExitProcess_loop
; Код выполняющийся если функция найдена
; ebp - адрес таблицы ординалов
; edx - индекс имени функции в таблице имен
found_ExitProcess:
    ; Получение абсолютного адреса функции по ее ординалу
    movzx eax, word [ebp + edx * 2]
    shl eax, 2
    add eax, edi
    mov eax, [eax]
    add eax, ebx
    ; Адрес функции найден. Ура! Можно что то делать дальше
    push eax ; <- адрес ExitProcess на стек
	

; Поиск адреса GetStdHandle
search_GetStdHandle:
    get_peb_addr eax ; eax <- адрес PEB
	get_ldr_addr eax, eax ; eax <- адрес LDR
    get_modules_list_addr eax, eax ; eax <- адрес списка модулей
    get_module_addr eax, 2, eax ; eax <- адрес модуля
    get_module_base_addr eax, ebx ; ebx <- базовый адрес модуля
	get_pe_header_addr ebx, eax ; eax <- адрес PE-заголовка модуля
	get_export_table_addr eax, ebx, eax ; eax <- адрес таблицы экспорта модуля
    mov edx, eax ; edx <- адрес таблицы экспорта модуля
    get_export_funcs_count eax, ecx ; ecx <- кол-во экспортируемых функций модуля
	get_funs_names_addr ebx, eax, esi ; esi <- адрес таблицы имен экспортируемых функций модуля
    get_funs_addrs_addr ebx, eax, edi ; edi <- адрес таблицы адресов экспортируемых функций модуля
    get_funs_ordinals_addr ebx, eax, ebp ; ebp <- адрес таблицы ординалов экспортируемых функций модуля
	; Поиск GetStdHandle
    xor edx, edx ; <- регистр выполняющий функцию счетчика
search_GetStdHandle_loop:
    ; Получаем адрес имени функции
    mov eax, [esi]
    add eax, ebx ; eax <- адрес имени функции
    ; Сравниваем с искомым именем
	SUPER_PUSH esi, edi, ecx, edx
    mov edi, esp
    sub edi, 64
    mov dword [edi], 'GetS'
    mov dword [edi+4], 'tdHa'
    mov dword [edi+8], 'ndle'
    mov byte [edi+12], 0
    compare_strings eax, edi, eax
	SUPER_POP edx, ecx, edi, esi
    ; Если строки равны
    test eax, eax
    jz found_GetStdHandle
    ; Иначе след. итерация
    add esi, 4 ; <- переход к адресу след. имени
    inc edx ; <- инкрементирование индекса
    loop search_GetStdHandle_loop ; выполняется ecx раз
GetStdHandle_not_found:
	pop ebx ; <- адрес ExitProcess
    push 1
    call ebx 
; Код выполняющийся если функция найдена
; ebp - адрес таблицы ординалов
; edx - индекс имени функции в таблице имен
found_GetStdHandle:
    ; Получение абсолютного адреса функции по ее ординалу
    movzx eax, word [ebp + edx * 2]
    shl eax, 2
    add eax, edi
    mov eax, [eax]
    add eax, ebx
    ; Адрес функции найден. Ура! Можно что то делать дальше
    pop ebx ; <- адрес ExitProcess
	push eax ; <- адрес GetStdHandle на стек
	call ebx ; <- вызов ExitProcess с адресом GetStdHandle в качестве аргумента
