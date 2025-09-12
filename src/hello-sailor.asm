; vim: set filetype=fasm :

format ELF64 executable

macro write fd, buf, count
{
    mov rax, 1
    mov rdi, fd
    mov rsi, buf
    mov rdx, count
    syscall
}

macro exit status 
{
   mov rax, 60
   mov rdi, status
   syscall
}

segment readable executable
entry main
main:
    repeat 10
        write 1, hello_sailor_msg, hello_sailor_msg_len
    end repeat
    exit 0

segment readable writeable
hello_sailor_msg db "Hello, Sailor!", 10
hello_sailor_msg_len = $ - hello_sailor_msg 
