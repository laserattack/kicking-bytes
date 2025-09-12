; vim: set filetype=fasm :

format PE console
entry start

section '.text' code readable executable

; ============================================================================
; ============================================================================
; ============================================================================

; ВСПОМОГАТЕЛЬНЫЕ МАКРОСЫ

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
; Сохранение на стеке адреса функции (принимает ее ординал)
macro save_func_addr ordinal {
    mov eax, [edi + (ordinal-1)*4]
    add eax, ebx
    push eax
}

; ============================================================================
; ============================================================================
; ============================================================================

; ОРДИНАЛЫ ФУНКЦИЙ

EXIT_PROCESS = 356
GET_STD_HANDLE = 728
WRITE_CONSOLE_A = 1549
CREATE_TOOLHELP32_SNAPSHOT = 258
CLOSE_HANDLE = 140
MODULE32_FIRST = 1000
MODULE32_NEXT = 1002
GET_LAST_ERROR = 615

; ============================================================================
; ============================================================================
; ============================================================================

macro print_string addr {
    push -11
    call dword [ebp+24]
    push eax
    mov eax, addr
	mov ebx,0
    strlen_loop:
        cmp byte [eax+ebx],0
        je strlen_end
        inc ebx
        jmp strlen_loop
    strlen_end:
	inc ebx
	pop eax
	super_push 0,0,ebx,ecx,eax
	call dword [ebp+20]
}

; ШЕЛЛКОД
start:
	; получение адресов секций peb
	peb_parse
	; адреса функций на стек
	save_func_addr GET_STD_HANDLE ; ebp + 24
	save_func_addr WRITE_CONSOLE_A ; ebp + 20
    save_func_addr EXIT_PROCESS ; ebp + 16
    save_func_addr CLOSE_HANDLE ; ebp + 12
    save_func_addr MODULE32_NEXT ; ebp + 8
    save_func_addr MODULE32_FIRST ; ebp + 4
    save_func_addr CREATE_TOOLHELP32_SNAPSHOT ; ebp + 0
	
	mov ebp, esp
    
payload:
    ; Создаем снимок процессов
	super_push 0, 0xF ; первым числом pid целевого процесса (должен быть 32 битный)
    call dword [ebp+0] ; CreateToolhelp32Snapshot

    cmp eax, -1
    je exit
    mov esi, eax ; esi <- хендл снимка

    ; Выделяем память под MODULEENTRY32
    sub esp, 1024
    mov edi, esp
    mov dword [edi], 1024
	
    ; Получаем первый модуль
    super_push edi, esi 
    call dword [ebp+4] ; Module32First
    test eax, eax
    jz cleanup ; нет модулей

module_loop:
	lea ecx, [edi+32]    ; ecx <- адрес имени модуля
	print_string ecx
	super_push edi, esi
    call dword [ebp+8] ; Module32Next
    test eax, eax
    jnz module_loop ; если еще есть модули

cleanup:
    ; Закрываем хэндл снимка
    push esi
    call dword [ebp+12] ; CloseHandle
    add esp, 1024
    
exit:
    ; ExitProcess(0)
    push 0
    call dword [ebp+16]
