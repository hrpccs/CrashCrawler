#! /bin/bash
echo "=============================================="
echo "Running the test script written for OScomp..."
echo "Crashcrawler is developed by Hong Ruipeng & Tang Zhe"
echo "The test scripts is written by Tang Zhe"
echo "Aug 12, 2022"
echo "=============================================="
SCRIPT_PATH=`realpath $0`
BASE_DIR=`dirname $SCRIPT_PATH`
SEGFAULT_PATH="$BASE_DIR/segfault"

CC=$(which gcc)
CFLAGS="-fopenmp"
# echo $BASE_DIR

pushd $SEGFAULT_PATH
    echo "Begin segment fault test..."
    for cnt in {1..7}
    do
        SRC="$cnt.c"
        BIN="$cnt.bin"
        $CC $CFLAGS $SRC -o $BIN
        ./$BIN
    done
    for slp in {1..100000}
    do
        SLP=1
    done
#    rm -rf *.bin
popd
echo "Finish Testing"
