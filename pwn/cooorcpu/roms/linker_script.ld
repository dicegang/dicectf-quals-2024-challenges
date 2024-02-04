ENTRY(main)
SECTIONS
{
    . = 16384;

    .text :
    {
        *(entry)
        *(.text)
    }
}
