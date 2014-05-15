利用llvm，实现一个pass，在程序llvm IR中插入代码，统计访存trace，支持多线程
在程序的每个load或者store指令之后插入调用showtrace的代码，showtrace实现在showtrace.c中。pass实现为memtrace.cpp文件位于llvm/lib/Transforms/Memtrace中。test.sh为测试脚本，hello.c为示例程序。

需求列表
1. 对于单线程
    基本功能：能够保存trace，对每一条访存指令（load|store，因为llvm ir是类RISC的）都插入代码记录访存的trace。(v1实现)
    具体：1> trace保存到缓冲区中，超过缓冲区时写到文件，考虑缓冲区的实现(速度、性能)和文件切分(保存成多个文件)、压缩等问题
          2> 实现一个cache模拟器，将trace输入到其中，得到落到内存上的访存情况，和cache miss、以及两个cache miss之间的访存次数（最好是命令条数             、时间）
          3> 研究依赖关系，两个目的：考虑内存模拟器执行的正确性，如下面的代码：
            load a from m1
            add a 1
            store a to m2
            这种隐含的相关性，在模拟器中是发现不了的，可能会被并行执行使得load或者运算之前就store了，找出这些依赖
            两个依赖之间隔着多少访存（最好是指令书甚至是时间）
          4> 源程序扩展：比如在源程序中加入一个标志，只对加了标志的代码进行优化
2. 对于多线程
    基本功能：分线程保存trace
    具体：1> 多个线程依赖，比如两个线程对同个地址访问的逻辑关系（相关领域：确定性重放）
