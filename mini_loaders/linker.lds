SECTIONS
{
  .text : { *(.text) }
  .rodata : { *(.rodata) }
  .bss : { *(.bss) }
  .data : { *(.data) }
  .LOAD : { *(.LOAD) }
}