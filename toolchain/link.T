SECTIONS {
	ENTRY(_start)
	. = 0x00400000;
	.text : { * (.text); }
	. = 0x00700000;
	.data : { * (.data); * (.rodata*); * (.sbss); * (.scommon); }
	.bss : { * (.bss); }
}
