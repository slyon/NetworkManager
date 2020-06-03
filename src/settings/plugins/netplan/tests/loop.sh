#!/bin/sh
MY_PATH="`dirname \"$0\"`"

# This is an infinite loop... unitl a segfault crashes it
# Let it run for a minute or so to check if the tests still crash randomly
until ! $MY_PATH/test-netplan; do
    if [ $? -eq 0 ]; then
        echo "##### Test failed #####"
	break
    else
	echo ""
        echo "##### All OK - re-run until segfault #####"
    fi
done
