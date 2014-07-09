clang -emit-llvm -c hello.c -o hello.bc
llvm-dis hello.bc
#clang -emit-llvm -c showtrace.c -o showtrace.bc
#llvm-dis showtrace.bc
#opt -load ~/llvm-3.4/build/Release+Asserts/lib/LLVMMemTrace.so -memtrace < hello.bc > /dev/null
opt -load ~/llvm-3.4/build/Release+Asserts/lib/LLVMMemTrace.so -memtrace < hello.bc > new.bc
llvm-dis new.bc
#clang new.bc showtrace.bc tmp.bc -lpthread -o all
llc new.bc -o new.s
gcc new.s -lshowtrace -lpthread -O2 -o new
#rm memtrace/*
gcc hello.c -O2 -o hello_naive -lpthread
