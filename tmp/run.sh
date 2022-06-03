#! /bin/bash
if [ -f *.bin ]; then
    rm *.bin
fi
gcc test.c -o test.bin 
echo "Finish Compilation..."
sudo ./test.bin