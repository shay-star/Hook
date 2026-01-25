# ABI

windows x64和linux x64的调用约定

### 跨平台

在linux中只有一种ABI.而`__cdecl`只在windows上存在
```cpp
#if defined(_MSC_VER)
#    define CC_CDECL __cdecl
#else
#    define CC_CDECL
#endif
```

### windows上调用约定处理

- `__cdecl`特化处理

```cpp
template <typename R, typename... Args> struct HookInvocation<R(__cdecl *)(Args...)> : HookContext
```


- `__fastcall`特化处理

```cpp
template <typename R, typename... Args> struct HookInvocation<R(__fastcall *)(Args...)> : HookContext
```

> 而在linux x64中只有一种调用约定
