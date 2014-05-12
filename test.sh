clang -emit-llvm -c hello2.c -o hello2.bc
llvm-dis hello2.bc
#clang -emit-llvm -c showtrace.c -o showtrace.bc
#llvm-dis showtrace.bc
#opt -load ~/llvm-3.4/build/Release+Asserts/lib/LLVMMemTrace.so -memtrace < hello.bc > /dev/null
opt -load ~/llvm-3.4/build/Release+Asserts/lib/LLVMMemTrace.so -memtrace < hello2.bc > new.bc
llvm-dis new.bc
#clang new.bc showtrace.bc tmp.bc -lpthread -o all
llc new.bc -o new.s
gcc new.s -lshowtrace -lpthread -O2 -o new
rm memtrace/*
