# Poirot

Poirot 是一个 Android ARM64 native Hook 检测项目，目前针对两类实现：wxshadow 一类同 VA 页切换 Hook，以及 `pte_hook` 一类跨 VA 执行重定向 Hook

仓库里的 App 只是测试壳，真正提供给开发者的是 `poirot.h` 和 `libpoirot.a`

## 使用

在需要保护的 native 函数开头加一行就行

```c
uint32_t hits = POIROT_HOOK_CHECK(
	POIROT_CHECK_TIMING |
	POIROT_CHECK_PROTECT |
	POIROT_CHECK_FORK);

if (poirot_hook_hits_detected(hits)) {
	/* hook detected */
}
```

`POIROT_HOOK_CHECK()` 返回命中的检测位，传入的 mask 只会求值一次，没有选中的项目不会运行

如果只关心最终结果，可以直接写

```c
if (POIROT_HOOK_DETECTED(POIROT_CHECK_DIAGNOSTIC)) {
	/* hook detected */
}
```


## 检测内容

### Shadow

这组检测针对 wxshadow 一类在同一个 VA 上切换 PTE 的实现

- `POIROT_CHECK_TIMING` 对比连续执行、交替读取执行和控制函数的耗时
- `POIROT_CHECK_SELFREAD` 从目标页内部读取 canary，观察读取视图和执行视图是否一致
- `POIROT_CHECK_PROTECT` 通过 `mprotect` 重建页面权限，再比较重建前后的页面内容
- `POIROT_CHECK_PARALLEL` 让两个线程同时读取和执行目标页，观察切页竞争留下的异常
- `POIROT_CHECK_FORK` 比较父子进程中的执行结果，子进程没有继承 Hook 时会直接暴露差异

Shadow 项容易受到调度、设备负载和具体 Hook 实现影响，所以默认至少命中两项才判定为 detected

### Redirect

这组检测针对 `pte_hook` 一类把原页设为 UXN，再把执行流送到另一个 clone VA 的实现

- `POIROT_CHECK_REDIRECT_FAULT` 在受控 `Data Abort` 中读取 signal frame，检查 fault PC 是否落在无 VMA 或不可执行的地址
- `POIROT_CHECK_REDIRECT_SIGNAL` 持续执行页内探针并向目标线程发送异步信号，检查是否反复采到无 VMA 的执行 PC
- `POIROT_CHECK_REDIRECT_GHOST` 使用前两项找到的地址，在子进程中验证这个无 VMA 页面是否仍然可读，并记录 `MAP_FIXED_NOREPLACE` 的结果

Redirect 的每一项都是强证据，任意一项命中就会判定为 detected

## 常用组合

- `POIROT_CHECK_SAFE` 只跑 timing，开销小，但单独命中不会直接判定 detected
- `POIROT_CHECK_DIAGNOSTIC` 跑完整诊断，不包含风险较高的 self-read
- `POIROT_CHECK_SHADOW_ALL` 打开全部 Shadow 检测
- `POIROT_CHECK_REDIRECT_ALL` 打开全部 Redirect 检测
- `POIROT_CHECK_ALL` 打开当前所有检测

这些检测是同步执行的，放在业务函数里就会跟着业务函数触发，也可以由按钮、定时器或风控策略低频调用

`PROTECT` 会修改并恢复目标页权限，属于侵入式检测，框架会把它放在最后执行

`SELFREAD` 默认不在 diagnostic 组合里，部分页切换实现可能在这里连续异常，用户态超时未必能把它救回来

## 测试函数

App 中的 `business_md5()` 是普通业务函数，函数开头运行检测，后面继续计算 MD5

MD5 只用于演示真实业务如何接入，不属于检测核心，也不会被打进静态 SDK

## 编译

```shell
./gradlew :app:assembleDebug
./gradlew :app:assembleRelease
```

编译完成后，SDK 会出现在

```text
app/build/poirot-sdk/{Debug,RelWithDebInfo}/
├── include/poirot.h
└── lib/arm64-v8a/libpoirot.a
```

## 目录

```text
app/src/main/cpp/
├── include/poirot.h
└── src/
    ├── main.c
    ├── crypto/
    ├── core/
    │   ├── shadow/
    │   │   └── probes/
    │   └── redirect/
    │       └── probes/
    └── utils/
```

## 边界

如果 Hook 完全替换目标函数，并且不再调用原函数，那么写在函数内部的检测自然没有机会执行。但是这里提供的思路不仅可以嵌入函数内同步检测，也可以采集上报，或是进程前后对比检测

检测结果也不是让 SDK 替业务做最终决策，调用方可以直接读取 `hits`，根据自己的场景调整触发频率和判定规则
