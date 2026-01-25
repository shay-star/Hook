HookContext 这个模板类（或其基类）的主要职责是：

- 持有 hook 相关的上下文（target_fn、detour_fn、trampoline 等）
- 提供静态的 InvocationEntry 函数（作为跳转目标）
- 根据 hook 类型（before/after/replace）决定调用顺序
- 处理 this 指针的传递（通过 fs:[-0x20] 或其他机制）
- 实现 invoke / dispatch 逻辑
- 保护钩子函数的可重入性质

它本质上是“**hook 调用时的执行上下文 + 分发器**”。


```cpp
struct HookContext {
    bool tl_reentrant[32]{false}; // 支持最多32个线程的重入保护
    std::uint8_t *target_fn{nullptr}; // 原函数地址
    std::uint8_t *detour_fn{nullptr}; // 用户传入的 hook 回调函数
    std::uint8_t *trampoline{nullptr};
    HookType hook_type;
    bool use_original_result{false};
};
```
- `tl_reentrant`这个字段不是共享的,因此需要为每个线程提供单独的工作区,来保存自己的数据
