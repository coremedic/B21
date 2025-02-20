.x64
.model flat, fastcall
option casemap:none
option win64:1

public Trampoline

.code

Trampoline PROC

    mov rbx, rdx                        ; Back up struct to rbx
    mov r11, [rbx]                      ; UINT_PTR      pfnApi
    mov r9,  [rbx + 08h]                ; UINT64        argCount

    cmp r9,  4                          ; Check if there are more than 4 args
    jle register_args                   ; If 4 or fewer args, just load registers

    mov r8,  r9                         ; Back up argCount to r8
    sub r8,  5                          ; Calculate index for last stack arg
    lea r10, [rbx + 030h]               ; Pointer to 5th arg in pArgs

stack_args:
    mov rdx, [r10 + r8*8]               ; Copy arg from pArgs to rdx
    mov [rsp + 028h + r8*8], rdx        ; Load arg onto stack
    dec r8                              ; Move to previous stack arg in pArgs
    jns stack_args                      ; Continue if more stack args remain

register_args:
    mov  rcx, [rbx + 010h]              ; Load 1st arg
    dec  r9                             ; Decrement argCount
    test r9, r9                         ; Check for more args
    jz   syscall_jmp                    ; 1 arg api call
    mov  rdx, [rbx + 018h]              ; Load 2nd arg
    dec  r9
    test r9, r9
    jz   syscall_jmp                    ; 2 arg api call
    mov  r8,  [rbx + 020h]              ; Load 3rd arg
    dec  r9
    test r9, r9
    jz   syscall_jmp                    ; 3 arg api call
    mov  r9,  [rbx + 028h]              ; Load 4th arg

syscall_jmp:
    jmp r11                             ; Jump to pfnApi

Trampoline ENDP

end