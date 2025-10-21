# 方案1 · VMX Root 新增核心模块示例用法

本文给出两个新模块在内核侧（HyperDbg VMM 环境）下的最小可用示例与注意事项：
- 模块 A：进程模块枚举器（VmmEnumerateProcessModules / VmmGetModuleBaseAddress）
- 模块 B：隐蔽内存读取封装（VmmStealthyReadProcessMemory）

适用范围：
- 在 HyperDbg 的 hyperhv（VMM）/ hyperkd（KD）内部调用，均在内核态执行。
- 采用 CR3 切换 + 物理页映射实现，绕过常见的内核/用户态 Hook，具备“隐蔽性”。

包含头文件：
- #include "memory/ModuleEnumerator.h"
- #include "interface/StealthyMemory.h"

注意：如果需要从 hyperkd 等其他模块调用，请确保将上述符号导出（可在 include/SDK/imports/kernel/HyperDbgVmmImports.h 中添加 IMPORT_EXPORT_VMM 声明，并在 hyperhv.def 或导出列表中开放）。本文示例默认在当前仓库工程内直接包含头文件并链接到 hyperhv。另外，实际项目中如遇非导出符号（如 PsGetProcessPeb/PsGetProcessWow64Process）在目标平台不可用的情况，可使用 ZwQueryInformationProcess(ProcessBasicInformation) 路径获取 PEB 基址作为替代。

---

## 1. 快速示例：枚举指定 PID 的用户态模块

示例目标：
- 第一次调用仅计数，第二次调用填充模块列表。

```c
#include "pch.h"
#include "memory/ModuleEnumerator.h"

VOID ExampleEnumerateModules(UINT32 Pid)
{
    NTSTATUS   status;
    UINT32     count = 0;

    // 1) 仅计数
    status = VmmEnumerateProcessModules(Pid, NULL, &count);
    if (!NT_SUCCESS(status) || count == 0) {
        LogInfo("[modules] pid=%u, count=%u, status=0x%08x", Pid, count, status);
        return;
    }

    // 2) 分配并填充
    PMODULE_INFO list = (PMODULE_INFO)PlatformMemAllocateZeroedNonPagedPool(sizeof(MODULE_INFO) * count);
    if (!list) {
        LogError("[modules] alloc failed");
        return;
    }

    UINT32 cap = count; // 传入容量，回填实际保存的个数
    status = VmmEnumerateProcessModules(Pid, list, &cap);
    if (!NT_SUCCESS(status)) {
        LogError("[modules] enumerate failed: 0x%08x", status);
        PlatformMemFreePool(list);
        return;
    }

    for (UINT32 i = 0; i < cap; ++i) {
        LogInfo("[%3u] base=%016llx size=%8llx name=%ws", i,
                list[i].BaseAddress, list[i].Size, list[i].ModuleName);
        // 可选：打印路径
        // LogInfo("      path=%ws", list[i].ModulePath);
    }

    PlatformMemFreePool(list);
}
```

要点：
- VmmEnumerateProcessModules(Pid, NULL, &count) 用于快速获取个数；
- 之后按 count 分配 MODULE_INFO 数组，第二次调用会填充结构体；
- 模块名与路径最大 260 字符，超长会被截断；
- 自动适配 WoW64/64 位进程（内部读取 PEB/LDR，遍历 InLoadOrderModuleList）。

---

## 2. 快速示例：查找模块基址

```c
#include "pch.h"
#include "memory/ModuleEnumerator.h"

UINT64 ExampleGetModuleBase(UINT32 Pid, const WCHAR* ModuleName)
{
    // 注意：当前比较为区分大小写的精确匹配
    UINT64 base = VmmGetModuleBaseAddress(Pid, ModuleName);
    if (base == 0) {
        LogInfo("[getbase] pid=%u name=%ws not found", Pid, ModuleName);
    } else {
        LogInfo("[getbase] pid=%u name=%ws base=%016llx", Pid, ModuleName, base);
    }
    return base;
}
```

要点：
- 当前实现使用 VmFuncVmxCompatibleWcscmp 进行字符串比较，为区分大小写的精确匹配；
- 如需不区分大小写，可在上层先统一大小写或扩展为不区分大小写比较；
- 返回 0 代表未找到或发生错误。

---

## 3. 快速示例：隐蔽读取远程进程内存

读取远程进程某虚拟地址的一段数据，自动处理跨页与物理映射。

```c
#include "pch.h"
#include "interface/StealthyMemory.h"

BOOLEAN ExampleReadRemote(UINT32 Pid, UINT64 Va, PVOID Buffer, SIZE_T Size)
{
    NTSTATUS status = VmmStealthyReadProcessMemory(Pid, Va, Buffer, Size);
    if (!NT_SUCCESS(status)) {
        LogError("[read] pid=%u va=%016llx size=%llu failed: 0x%08x", Pid, Va, Size, status);
        return FALSE;
    }
    return TRUE;
}
```

要点：
- 内部按页分块，使用 VirtualAddressToPhysicalAddressByProcessCr3 + MemoryMapperReadMemorySafeByPhysicalAddress 实现；
- 不依赖 Zw/Ke 用户态可见 API，避免被 Hook；
- Buffer 不可为 NULL，Size 必须 > 0；
- 若目标虚拟地址未映射或转换失败，返回 STATUS_INVALID_ADDRESS。

---

## 4. 综合示例：读取模块 PE 头签名（"MZ"）

```c
#include "pch.h"
#include "memory/ModuleEnumerator.h"
#include "interface/StealthyMemory.h"

VOID ExampleReadPeHeader(UINT32 Pid, const WCHAR* ModuleName)
{
    UINT64 base = VmmGetModuleBaseAddress(Pid, ModuleName);
    if (base == 0) {
        LogInfo("[mz] module not found: %ws", ModuleName);
        return;
    }

    BYTE mz[2] = {0};
    NTSTATUS st = VmmStealthyReadProcessMemory(Pid, base, mz, sizeof(mz));
    if (!NT_SUCCESS(st)) {
        LogError("[mz] read failed: 0x%08x", st);
        return;
    }

    if (mz[0] == 'M' && mz[1] == 'Z') {
        LogInfo("[mz] %ws @ %016llx -> MZ header OK", ModuleName, base);
    } else {
        LogInfo("[mz] %ws @ %016llx -> invalid header: %02x %02x", ModuleName, base, mz[0], mz[1]);
    }
}
```

---

## 返回值与错误处理
- VmmEnumerateProcessModules
  - STATUS_INVALID_PARAMETER：入参不合法或 PID 无效；
  - STATUS_SUCCESS：成功；
- VmmGetModuleBaseAddress
  - 返回 0：未找到或 PID/读取失败；
- VmmStealthyReadProcessMemory
  - STATUS_INVALID_PARAMETER：Buffer 为空或 Size=0，或 PID/CR3 获取失败；
  - STATUS_INVALID_ADDRESS：VA->PA 转换失败（未映射/无效地址）；
  - STATUS_UNSUCCESSFUL：物理读取失败；
  - STATUS_SUCCESS：成功。

---

## 实现细节摘要（供排障参考）
- 模块枚举：
  - 通过 PsLookupProcessByProcessId 确认 EPROCESS 存在；
  - WoW64/64 位自动分流；
  - 读取 PEB->Ldr 并遍历 InLoadOrder 链表，逐项读取 LDR_DATA_TABLE_ENTRY；
  - 将 BaseAddress/Size/Name/Path 填入 MODULE_INFO；
- 隐蔽读取：
  - 先以目标进程 CR3 将 VA 转换为 PA；
  - 基于预分配 PTE 映射物理页，并 memcpy 出数据，自动处理跨页；

---

## 常见问题（FAQ）
- Q: 这些函数能否在 VMX root 下直接调用？
  - A: 可以，这些实现完全在 VMM 内核侧，未依赖 Zw* 等敏感 API；
- Q: 模块名大小写是否敏感？
  - A: 当前实现为区分大小写（wcscmp）。如需不区分大小写，请在调用前统一大小写或扩展为不区分大小写比较；
- Q: 是否支持超长路径？
  - A: 目前 MODULE_INFO 的路径与名称缓冲固定为 260 字符，超出将被截断；

---

## 参考
- 代码位置：
  - 隐蔽读取：hyperhv/code/interface/StealthyMemory.c, header/interface/StealthyMemory.h
  - 模块枚举：hyperhv/code/memory/ModuleEnumerator.c, header/memory/ModuleEnumerator.h
- 相关基元：
  - CR3 获取：hyperhv/code/memory/Layout.c
  - VA->PA：hyperhv/code/memory/Conversion.c
  - 物理读取：hyperhv/code/memory/MemoryMapper.c
