; Dynamically linked
; This is assembled into a dynamic library, providing the msg symbol

        global msg:data msg.end-msg

        section .data

msg:    db "hi there", 10

 .end:
