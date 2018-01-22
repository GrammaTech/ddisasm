clang $1.c -o $1
clang -S $1.c -o $1.s
offset_main=$(readelf -s $1 | grep ' main' | awk '{print $2}' )
offset_text=$(readelf -S $1 | grep '.text' | awk '{print $4}' )

echo "Code $offset_text"
echo "Main $offset_main"
objcopy -O binary --only-section=.text $1 $1.text
./x64show  -f=$1.text -address=0x$offset_main -omit-prefix > $1.dec
echo "entry($offset_main)" >> $1.dec
./x64show  -f=$1.text -address=0x$offset_main -omit-prefix -asm > $1.asm

