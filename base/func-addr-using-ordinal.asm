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
    mov eax, ordinal-1
    shl eax, 2
    add eax, edi
    mov eax, [eax]
    add eax, ebx
    push eax ; <- адрес функции на стек
}

; ============================================================================
; ============================================================================
; ============================================================================

; тут ординалы функций используемых (по ним ищутся адреса)

EXIT_PROCESS = 356

; ============================================================================
; ============================================================================
; ============================================================================

; ШЕЛЛКОД
start:

; получение адресов секций peb
peb_parse

; спушит адрес функции на стек
save_func_addr EXIT_PROCESS
	
payload:
	mov ebp, esp

    ; Завершаем процесс с кодом 0
    push 0
    call dword [ebp+0]
