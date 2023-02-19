## Specific architecture limitations

### AARCH64

arm in 64 bit mode generate adrl instruction.
These instructions are (2 ** 12) aligned (page) therfore the shellcode should be
page aligned to overcome this limitation the shellcode is padded
