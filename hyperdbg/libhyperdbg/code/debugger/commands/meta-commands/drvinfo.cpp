/**
 * @file drvinfo.cpp
 * @author HyperDbg Team
 * @brief .drvinfo command
 * @details Shows driver/device randomization details (resolved device path,
 *          registry-persisted suffix, and DOS device name) to verify that
 *          the debugger driver randomized its public identifiers.
 */
#include "pch.h"

/**
 * @brief help of the .drvinfo command
 *
 * @return VOID
 */
VOID
CommandDrvinfoHelp()
{
    ShowMessages(".drvinfo | drvinfo : shows current driver/device randomization details.\n\n");
    ShowMessages("syntax : \t.drvinfo\n");
    ShowMessages("syntax : \tdrvinfo\n");
}

static void ResolveHyperDbgDevicePathA(char* outBuffer, size_t outBufferSize)
{
    // Default fallback to backward-compatible static name
    strcpy_s(outBuffer, outBufferSize, HYPERDBG_USER_DEVICE_NAME);

    HKEY  hKey = NULL;
    char  regPath[256] = {0};
    DWORD suffix       = 0;
    DWORD type         = 0;
    DWORD cbData       = sizeof(suffix);

    sprintf_s(regPath, sizeof(regPath), "SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters", KERNEL_DEBUGGER_DRIVER_NAME);

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, regPath, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS)
    {
        // Prefer explicit user-mode path if the driver provided it
        char userName[260] = {0};
        DWORD cbUser       = sizeof(userName);
        type               = 0;
        if (RegQueryValueExA(hKey, "UserDeviceName", NULL, &type, (LPBYTE)userName, &cbUser) == ERROR_SUCCESS && type == REG_SZ && userName[0] != '\0')
        {
            strncpy_s(outBuffer, outBufferSize, userName, _TRUNCATE);
            RegCloseKey(hKey);
            return;
        }

        // Next, use the persisted DOS device name directly if present
        char dosName[260] = {0};
        cbData            = sizeof(dosName);
        type              = 0;
        if (RegQueryValueExA(hKey, "DosDeviceName", NULL, &type, (LPBYTE)dosName, &cbData) == ERROR_SUCCESS && type == REG_SZ)
        {
            // Typically of the form "\\\\DosDevices\\\\<leaf>-XXXX" or "\\\\??\\\\<leaf>-XXXX"
            const char* tail      = dosName;
            const char* lastSlash = strrchr(dosName, '\\');
            if (lastSlash && lastSlash[1] != '\0')
            {
                tail = lastSlash + 1;
            }
            sprintf_s(outBuffer, outBufferSize, "\\\\.\\%s", tail);
            RegCloseKey(hKey);
            return;
        }

        // Fallback: use the numeric suffix persisted by the driver with compile-time base
        if (RegQueryValueExA(hKey, "DeviceSuffix", NULL, &type, (LPBYTE)&suffix, &cbData) == ERROR_SUCCESS && type == REG_DWORD)
        {
            sprintf_s(outBuffer, outBufferSize, "%s-%04X", HYPERDBG_USER_DEVICE_NAME_BASE, suffix);
            RegCloseKey(hKey);
            return;
        }

        RegCloseKey(hKey);
    }

    // Fallback 2: enumerate DOS device namespace and pick the first matching our randomized pattern
    // Derive base leaf name from "\\\\.\\RtlCoreIo" -> "RtlCoreIo"
    const char* baseLeaf  = HYPERDBG_USER_DEVICE_NAME_BASE;
    const char* lastSlash = strrchr(baseLeaf, '\\');
    if (lastSlash && lastSlash[1] != '\0')
    {
        baseLeaf = lastSlash + 1;
    }

    char  queryBuf[4096] = {0};
    DWORD chars          = QueryDosDeviceA(NULL, queryBuf, (DWORD)sizeof(queryBuf));
    if (chars != 0)
    {
        // Multi-string iteration
        for (char* p = queryBuf; *p; p += strlen(p) + 1)
        {
            if (_strnicmp(p, baseLeaf, strlen(baseLeaf)) == 0)
            {
                // Ensure randomized form like "<base>-XXXX"
                if (p[strlen(baseLeaf)] == '-')
                {
                    sprintf_s(outBuffer, outBufferSize, "\\\\.\\%s", p);
                    return;
                }
            }
        }
    }

    // If all else fails, outBuffer remains the static base (backward compatibility)
}

static void ReadRandomizationRegistry(DWORD* outSuffix, std::string& outDosName, std::string& outUserName, bool& hasSuffix, bool& hasDosName, bool& hasUserName)
{
    hasSuffix   = false;
    hasDosName  = false;
    hasUserName = false;
    *outSuffix  = 0;
    outDosName.clear();
    outUserName.clear();

    HKEY  hKey = NULL;
    char  regPath[256] = {0};
    sprintf_s(regPath, sizeof(regPath), "SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters", KERNEL_DEBUGGER_DRIVER_NAME);

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, regPath, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS)
    {
        DWORD type   = 0;
        DWORD suffix = 0;
        DWORD cbData = sizeof(suffix);
        if (RegQueryValueExA(hKey, "DeviceSuffix", NULL, &type, (LPBYTE)&suffix, &cbData) == ERROR_SUCCESS && type == REG_DWORD)
        {
            *outSuffix = suffix;
            hasSuffix  = true;
        }

        char  dosName[260] = {0};
        cbData             = sizeof(dosName);
        type               = 0;
        if (RegQueryValueExA(hKey, "DosDeviceName", NULL, &type, (LPBYTE)dosName, &cbData) == ERROR_SUCCESS && type == REG_SZ)
        {
            outDosName.assign(dosName);
            hasDosName = true;
        }

        char  userName[260] = {0};
        cbData              = sizeof(userName);
        type                = 0;
        if (RegQueryValueExA(hKey, "UserDeviceName", NULL, &type, (LPBYTE)userName, &cbData) == ERROR_SUCCESS && type == REG_SZ)
        {
            outUserName.assign(userName);
            hasUserName = true;
        }

        RegCloseKey(hKey);
    }
}

/**
 * @brief .drvinfo and drvinfo command handler
 */
VOID
CommandDrvinfo(std::vector<CommandToken> CommandTokens, std::string Command)
{
    if (CommandTokens.size() != 1)
    {
        ShowMessages("incorrect use of the '%s'\n\n",
                     GetCaseSensitiveStringFromCommandToken(CommandTokens.at(0)).c_str());
        CommandDrvinfoHelp();
        return;
    }

    // Read registry-persisted randomization artifacts
    DWORD       suffix      = 0;
    std::string dosNameReg;
    std::string userNameReg;
    bool        hasSuffix   = false;
    bool        hasDosName  = false;
    bool        hasUserName = false;
    ReadRandomizationRegistry(&suffix, dosNameReg, userNameReg, hasSuffix, hasDosName, hasUserName);

    // Resolve the user-mode device path as the debugger currently expects
    char resolvedPath[256] = {0};
    ResolveHyperDbgDevicePathA(resolvedPath, sizeof(resolvedPath));

    // Derive the leaf name from base (e.g., RtlCoreIo)
    const char* baseLeaf  = HYPERDBG_USER_DEVICE_NAME_BASE;
    const char* lastSlash = strrchr(baseLeaf, '\\');
    if (lastSlash && lastSlash[1] != '\0')
    {
        baseLeaf = lastSlash + 1;
    }

    // Compose what the randomized names should look like (if data exists)
    char expectedUserPath[260] = {0};
    char expectedDosPath[260]  = {0};

    if (hasUserName)
    {
        strncpy_s(expectedUserPath, sizeof(expectedUserPath), userNameReg.c_str(), _TRUNCATE);
    }
    else if (hasDosName)
    {
        // Build from DOS name's tail
        const char* tail      = dosNameReg.c_str();
        const char* lastSlash2 = strrchr(tail, '\\');
        if (lastSlash2 && lastSlash2[1] != '\0')
        {
            tail = lastSlash2 + 1;
        }
        sprintf_s(expectedUserPath, sizeof(expectedUserPath), "\\\\.\\%s", tail);
    }
    else if (hasSuffix)
    {
        // Fallback to compile-time base + suffix (legacy)
        sprintf_s(expectedUserPath, sizeof(expectedUserPath), "\\\\.\\%s-%04X", baseLeaf, suffix);
    }

    if (hasDosName)
    {
        strncpy_s(expectedDosPath, sizeof(expectedDosPath), dosNameReg.c_str(), _TRUNCATE);
    }
    else if (hasSuffix)
    {
        // Legacy expectation (namespace might differ at runtime)
        sprintf_s(expectedDosPath, sizeof(expectedDosPath), "\\\\DosDevices\\\\%s-%04X", baseLeaf, suffix);
    }

    // Print results
    ShowMessages("service name           : %s\n", KERNEL_DEBUGGER_DRIVER_NAME);
    ShowMessages("resolved user path     : %s\n", resolvedPath);

    if (hasSuffix)
    {
        ShowMessages("device suffix (REG_DWORD) : 0x%04X\n", suffix & 0xFFFF);
    }
    else
    {
        ShowMessages("device suffix (REG_DWORD) : <not found>\n");
    }

    if (hasDosName)
    {
        ShowMessages("dos device (REG_SZ)   : %s\n", dosNameReg.c_str());
    }
    else
    {
        ShowMessages("dos device (REG_SZ)   : <not found>\n");
    }

    // Indicate whether randomization is in effect
    bool looksRandomized = false;

    if (hasUserName)
    {
        // Inspect the base and suffix in the user-mode name ("\\\\.\\<base>-XXXX")
        const char* p = userNameReg.c_str();
        const char* leaf = p;
        const char* slash = strrchr(p, '\\');
        if (slash && slash[1] != '\0')
        {
            leaf = slash + 1;
        }
        const char* dash = strchr(leaf, '-');
        if (dash && (dash[1] && dash[2] && dash[3] && dash[4]))
        {
            // Check hex-ish pattern and that base != default baseLeaf
            bool hexish = isxdigit((unsigned char)dash[1]) && isxdigit((unsigned char)dash[2]) && isxdigit((unsigned char)dash[3]) && isxdigit((unsigned char)dash[4]);
            char baseBuf[128] = {0};
            size_t baseLen = (size_t)(dash - leaf);
            if (baseLen < sizeof(baseBuf))
            {
                memcpy(baseBuf, leaf, baseLen);
                baseBuf[baseLen] = '\0';
            }
            looksRandomized = hexish && _stricmp(baseBuf, baseLeaf) != 0;
        }
    }
    else if (hasSuffix)
    {
        // If we have suffix only, best-effort: resolved path contains "-XXXX"
        const char* dash = strchr(resolvedPath, '-');
        looksRandomized  = (dash != nullptr);
    }

    ShowMessages("randomization active   : %s\n", looksRandomized ? "yes" : "no");

    if (expectedUserPath[0] != '\0')
    {
        ShowMessages("expected (user)       : %s\n", expectedUserPath);
    }
    if (expectedDosPath[0] != '\0')
    {
        ShowMessages("expected (dos)        : %s\n", expectedDosPath);
    }

    ShowMessages("note: values are read from HKLM\\SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters and DOS device namespace.\n",
                 KERNEL_DEBUGGER_DRIVER_NAME);
}
