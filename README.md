# Poirot

Poirot 用来在 Android ARM64 用户层识别 wxshadow 一类会切换代码页 PTE 的 Hook。

App 中的 `business_md5()` 是一个普通业务函数：函数开头通过 `POIROT_HOOK_CHECK()` 保护自身，随后调用 `crypto/md5.c` 完成正常计算。MD5 不属于检测核心，也不会被编入 Poirot 静态 SDK。

开发者只需要包含 `poirot.h`，并在需要保护的 native 函数开头放一行：

```c
uint32_t hits = POIROT_HOOK_CHECK(
	POIROT_CHECK_TIMING |
	POIROT_CHECK_PROTECT |
	POIROT_CHECK_FORK);

if (poirot_hook_hits_detected(hits)) {
	/* 至少两项检测命中，判定存在 wxshadow-like Hook。 */
}
```

业务函数不需要专用 section、固定地址对齐或额外函数属性。

如果只关心有没有命中，也可以写成：

```c
if (POIROT_HOOK_DETECTED(POIROT_CHECK_DIAGNOSTIC)) {
	/* wxshadow-like hook detected */
}
```

`POIROT_HOOK_CHECK()` 返回命中的检测位，传入的 mask 只会求值一次，没有选中的检测不会运行。
默认判定规则是五项检测中任意两项命中：单项命中为 anomalous，两项及以上为 detected。调用方仍可直接读取命中位图，采用自己的判定策略。

- `POIROT_CHECK_SAFE`：只运行轻量的时序检测，适合放在正常业务路径；它只能产生单项证据，不会独立得到 detected 结论。
- `POIROT_CHECK_DIAGNOSTIC`：运行除同页自读外的完整检测，开销较大，其中权限重建具有侵入性。
- `POIROT_CHECK_SELFREAD`：只建议测试时显式开启。部分实现可能在同页读写切换中无限异常，用户层超时不一定有机会打断。

宏应放在函数开头附近。如果 Hook 完全替换了目标函数且不再调用原函数，检测代码本身不会得到执行，这是所有函数内自检都绕不开的边界。

执行 `./gradlew :app:assembleDebug` 后，会同时生成便于集成的头文件和静态库：

```text
app/build/poirot-sdk/{Debug,RelWithDebInfo}/
├── include/poirot.h
└── lib/arm64-v8a/libpoirot.a
```
