ENTRY(main)
SECTIONS
{
    . = 0;

    .text :
    {
        *(entry)
        *(.text)
    }
}
