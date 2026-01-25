它实现了：

- 安全的 hook 开/关
- 灵活的调用顺序
- 支持成员函数回调
- 支持返回值选择
- 线程安全的实例获取


### 线程安全

inline hook 在多线程环境中很危险，因为 trampoline 是共享的代码。如果 100 个线程同时调用被 hook 函数，trampoline 必须为每个线程提供独立的“工作区”（上下文），否则寄存器现场会被覆盖。

固定上限 vs. 动态分配：选择固定 32 是权衡性能和复杂度的结果。动态分配（e.g., 用 malloc/new）在 trampoline（汇编代码）中很难实现，且有锁开销。固定池用原子操作（xchg / cmpxchg）抢占槽位，无锁、快速。
如果超过 32：行为未定义（通常是无限循环在借上下文时，或覆盖已有上下文，导致崩溃）。作者认为 32 足够，因为 hook 通常不是高并发热点。

### 实现

该项目,在hook我们需要保存this指针传递给给hook函数使用,考虑到多线程保护,该钩子实例需要对每个线程都有自己的工作区来保存传递自己线程的数据,这样每个线程都能找到“属于自己的” Hook 实例

1. 使用 `TIB.ArbitraryUserPointer` 来保存当前**Hook**实例指针（非常经典的线程局部存储技巧）
2. 每个线程申请一块属于自己的内存作为工作区


我们使用第一种方法

### 具体分析

|架构|寄存器|代码写法|实际写入位置|这是什么？|线程相关吗？|常见真实用途|
|---|---|---|---|---|---|---|
|windows x32|FS|mov fs:[0x14], this|FS:[0x14]|TEB 的 Arbitrary data slot (用户自定义槽)|是|自定义线程数据、this 指针、上下文指针|
|windows x64|GS|mov gs:[0x28], this|GS:[0x28]|TEB 的 Arbitrary data slot (用户自定义槽)|是|同上，常用于保存 C++ 对象指针、hook 上下文|

### 为什么说它是线程相关的？

- **每个线程都有自己独立的 TEB** Windows 在线程切换时会自动修改 FS/GS 寄存器的基地址（通过 GDT 或 MSR），所以 → 线程 A 写 gs:[0x28] = 0xAAAA → 线程 B 写 gs:[0x28] = 0xBBBB 两者互不干扰
- 这个槽位（fs:[0x14] / gs:[0x28]）**官方定义就是给用户程序随意使用的** 微软文档和 Wine 源码里都叫它 **Arbitrary data slot** 或 **ArbitraryUserPointer** → 非常适合用来存“当前线程的上下文对象”（this 指针是最常见的做法）


### 考虑函数的可重入性
call targetFunction -> detourFunction
call Function1
call Function2
...
call targetFunction


如果发生这样的情况,就要考虑detourFunction是否可重入,会不会发生无限递归,比如原函数是底层函数做了递归终止条件,而detourFunction没有实现,或是考虑递归深度
- case 1:call targetFunction
- case 2:call detourFunction

### 注意事项

1. 该代码中linux的fs:[-0x20]只是为了演示,并没有windows上的作用
2. 写入机器码时,并不是原子性保护




### 刷新指令缓存

```cpp
#if defined(_MSC_VER)
        FlushInstructionCache(GetCurrentProcess(), NULL, 0);
#elif defined(__GNUC__) || defined(__clang__)
        __builtin___clear_cache(invocation_prologue, invocation_prologue + length);
#else
#endif
```

> 保证指定进程在指定内存范围内，之后执行到的指令，一定来自最新的内存内容
