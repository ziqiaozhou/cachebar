IMG=qemu-image.img
DIR=mount-point.dir
qemu-img create $IMG 1g
mkfs.ext2 $IMG
mkdir $DIR
sudo mount -o loop $IMG $DIR
sudo debootstrap --arch amd64 jessie $DIR
sudo umount $DIR
#rmdir $DIR
sudo chroot $DIR
