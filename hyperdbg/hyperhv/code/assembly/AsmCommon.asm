PUBLIC AsmStiInstruction
PUBLIC AsmCliInstruction
PUBLIC AsmGetRflags
PUBLIC AsmReloadGdtr
PUBLIC AsmReloadIdtr

.code _text

;------------------------------------------------------------------------

AsmStiInstruction PROC PUBLIC

    sti
    ret

AsmStiInstruction ENDP 

;------------------------------------------------------------------------

AsmCliInstruction PROC PUBLIC

    cli
    ret

AsmCliInstruction ENDP 

;------------------------------------------------------------------------

AsmGetRflags PROC
    
    pushfq
    pop		rax
    ret
    
AsmGetRflags ENDP

;------------------------------------------------------------------------

; AsmReloadGdtr (PVOID GdtBase (rcx), UINT32 GdtLimit (rdx) );

AsmReloadGdtr PROC

    push	rcx
    shl		rdx, 48
    push	rdx
    lgdt	fword ptr [rsp+6]	; do not try to modify stack selector with this ;)
    pop		rax
    pop		rax
    ret
    
AsmReloadGdtr ENDP

;------------------------------------------------------------------------

; AsmReloadIdtr (PVOID IdtBase (rcx), UINT32 IdtLimit (rdx) );

AsmReloadIdtr PROC
    
    push	rcx
    shl		rdx, 48
    push	rdx
    lidt	fword ptr [rsp+6]
    pop		rax
    pop		rax
    ret
    
AsmReloadIdtr ENDP

;------------------------------------------------------------------------

; AsmWriteSsp (void * AddressToWriteIntoSsp );

AsmWriteSsp PROC
    
    ; Use RSTORSSP instruction to restore SSP from memory pointed by RCX
    rstorssp qword ptr [rcx]    ; Restores SSP from the address in RCX

    ; Return from the function (uses the return address in SSP)
    ret

AsmWriteSsp ENDP

;------------------------------------------------------------------------

; AsmReadSsp ( );

AsmReadSsp PROC

    ; Save the current SSP to a memory location
    RDSSPQ rax  ; Save SSP to memory at the current location (stack pointer)

    ; Return from the function
    ret

AsmReadSsp ENDP

;------------------------------------------------------------------------

END                     