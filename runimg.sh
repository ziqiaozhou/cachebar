qemu-system-x86_64 -kernel $1  \
	-hda qemu-image.img\
	-append "root=/dev/sda"\
	-nographic\
	-curses\
	-enable-kvm

	#-append "root=/dev/sda console=ttyS0"\
