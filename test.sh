#!/bin/sh

cc -lcurl -fsanitize=address -ggdb3 test.c && ./a.out
