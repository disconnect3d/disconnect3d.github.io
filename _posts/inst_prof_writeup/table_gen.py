from pwn import asm


BANNER = '''
| Opcodes       | Bytes | Instructions   |                  Comment                 |
|---------------|:-----:|----------------|:----------------------------------------:|'''

ENDING = '|               |       |                |                                          |'

template = '| {opcodes}    | {bytes} | {instr}     | {comment} |'

SOFT_SPACE = '&nbsp;'

instructions = (
    ('xor rax, rax', ''),
    ('xor eax, eax', 'zeroes rax register'),
    ('mov rbx, 1', 'too big to use'),
    ('mov ebx, 1', 'too big to use'),
    ('mov bx, 1', ''),
    ('dec edx', ''),
    ('inc edx', ''),
    ('inc r15', ''),
    ('mov r13, r14', ''),
    ('mov r15, [r14]', ''),
    ('mov r15, [r14+32]', ''),
    ('mov [r15], r14', ''),
    ('mov [r15+64], r14', 'max offset for 4B instruction is 127'),
    ('mov [r15+128], r14', 'too big to use'),
    ('lea r15, [r13+127]', 'max offset for 4B instruction is 127')
)

print(BANNER)
for instr, comment in instructions:
    if not comment:
        comment = '-'

    opcodes = asm(instr, os='linux', arch='amd64')
    opcodes_hex = opcodes.encode('hex')
    opcodes_hex = ' '.join(opcodes_hex[i:i+2] for i in range(0, len(opcodes_hex), 2))

    instr = instr.replace(' ', SOFT_SPACE)
    opcodes_hex = opcodes_hex.replace(' ', SOFT_SPACE)

    msg = template.format(
        instr=instr, opcodes=opcodes_hex, bytes=len(opcodes), comment=comment
    )

    print(msg)
print(ENDING)
