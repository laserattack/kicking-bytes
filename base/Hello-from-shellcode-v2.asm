; vim: set filetype=fasm :

format PE console
entry start

section '.text' code readable executable

; ВСПОМОГАТЕЛЬНЫЕ МАКРОСЫ

; ============================================================================
; ============================================================================
; ============================================================================

; Макрос для пуша всех переданных аргументов в стек
macro super_push [args] {
    forward
    push args
}
; Макрос для попа нескольких значений из стека  
macro super_pop [args] {
    forward
    pop args
}

macro push_string [bytes] {
    common
        local ..counter
        ..counter = 0
        ; Используем существующее место на стеке
        mov edi, esp
        sub edi, 512  ; Используем буфер на стеке
    forward
        mov byte [edi + ..counter], bytes
        ..counter = ..counter + 1
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
	super_push esi, edi, ecx
    
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
	super_pop ecx, edi, esi
}

; ДАЛЕЕ МАКРОСЫ ВЫПОЛНЕНИЕ КОРРЕКТНОЕ ВЫПОЛНЕНИЕ КОТОРЫХ ЗАВИСИТ ОТ КОНТЕКСТА
; ЭТИ МАКРОСЫ НУЖНЫ ПРОСТО ЧТОБЫ ИЗБЕЖАТЬ ПОВТОРЕНИЙ КОДА ПРИ ПОИСКЕ РАЗНЫХ ФУНКЦИЙ

; Подготовка к поиску функции
macro peb_parse {
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
}
; Сохранение на стеке найденного адреса функции
macro save_func_addr {
	; Получение абсолютного адреса функции по ее ординалу
    movzx eax, word [ebp + edx * 2]
    shl eax, 2
    add eax, edi
    mov eax, [eax]
    add eax, ebx
    ; Адрес функции найден. Ура! Можно что то делать дальше
    push eax ; <- адрес на стек
}

; ============================================================================
; ============================================================================
; ============================================================================

; ШЕЛЛКОД
start:

; Поиск адреса ExitProcess
search_ExitProcess:
	peb_parse
	; Поиск ExitProcess
    xor edx, edx ; <- регистр выполняющий функцию счетчика
search_ExitProcess_loop:
    ; Получаем адрес имени функции
    mov eax, [esi]
    add eax, ebx ; eax <- адрес имени функции
    ; Сравниваем с искомым именем
	super_push esi, edi, ecx, edx
    push_string 'E','x','i','t','P','r','o','c','e','s','s',0x00
    compare_strings eax, edi, eax
	super_pop edx, ecx, edi, esi
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
    save_func_addr
	

; Поиск адреса GetStdHandle
search_GetStdHandle:
    peb_parse
	; Поиск GetStdHandle
    xor edx, edx ; <- регистр выполняющий функцию счетчика
search_GetStdHandle_loop:
    ; Получаем адрес имени функции
    mov eax, [esi]
    add eax, ebx ; eax <- адрес имени функции
    ; Сравниваем с искомым именем
	super_push esi, edi, ecx, edx
    push_string 'G','e','t','S','t','d','H','a','n','d','l','e',0x00
    compare_strings eax, edi, eax
	super_pop edx, ecx, edi, esi
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
    save_func_addr
	
	
; Поиск адреса WriteConsoleA
search_WriteConsoleA:
    peb_parse
	; Поиск WriteConsoleA
    xor edx, edx ; <- регистр выполняющий функцию счетчика
search_WriteConsoleA_loop:
    ; Получаем адрес имени функции
    mov eax, [esi]
    add eax, ebx ; eax <- адрес имени функции
    ; Сравниваем с искомым именем
	super_push esi, edi, ecx, edx
	push_string 'W','r','i','t','e','C','o','n','s','o','l','e','A',0x00
    compare_strings eax, edi, eax
	super_pop edx, ecx, edi, esi
    ; Если строки равны
    test eax, eax
    jz found_WriteConsoleA
    ; Иначе след. итерация
    add esi, 4 ; <- переход к адресу след. имени
    inc edx ; <- инкрементирование индекса
	dec ecx
    jnz search_WriteConsoleA_loop
    jmp WriteConsoleA_not_found
WriteConsoleA_not_found:
	pop ebx ; <- адрес ExitProcess
    push 1
    call ebx 
; Код выполняющийся если функция найдена
; ebp - адрес таблицы ординалов
; edx - индекс имени функции в таблице имен
found_WriteConsoleA:
	save_func_addr
	
	
; После того как найдены все адреса, можно выполнять полезную нагрузку
payload:


	; Устанавливаем ebp как базовый указатель на стек
	mov ebp, esp  ; Теперь ebp указывает на вершину стека

	; На стеке:
	; [ebp]     -> WriteConsoleA
	; [ebp+4]   -> GetStdHandle
	; [ebp+8]   -> ExitProcess

	; Получаем хендл стандартного вывода (STD_OUTPUT_HANDLE = -11)
	push -11
	call dword [ebp+4]  ; Вызов GetStdHandle(-11)
	; Теперь в eax хендл стандартного вывода

	; Подготавливаем строку для вывода на стек
	push_string 'h','e','l','l','o',' ','f','r','o','m',' ','s','h','e','l','l','c','o','d','e','!','!',0x0A,0x00

	; Вызываем WriteConsoleA
	super_push 0,0,23,edi,eax
	call dword [ebp]              ; Вызов WriteConsoleA


    ; Завершаем процесс с кодом 0
    push 0
    call dword [ebp+8]            ; Вызов ExitProcess(0)
