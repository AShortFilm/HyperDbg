/**
* @file hyperdbg-cli.cpp
* @author Sina Karvandi (sina@hyperdbg.org)
* @brief Main HyperDbg Cli source coede
* @details
* @version 0.1
* @date 2020-04-11
*
* @copyright This project is released under the GNU Public License v3.
*
*/

//
// Environment headers
//
#include "platform/user/header/Environment.h"

#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <conio.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <cctype>
#include <sstream>

#include "SDK/HyperDbgSdk.h"
#include "SDK/imports/user/HyperDbgLibImports.h"

using namespace std;

static string to_lower_copy(const string & s);

static string g_captured_output;

static int hyperdbg_capture_messages(const char * Text)
{
   if (Text)
   {
       g_captured_output.append(Text);
   }
   return 0;
}

// Cached command list for interactive auto-complete
static bool              g_commands_loaded = false;
static vector<string>    g_all_commands;

static void ensure_command_list_loaded()
{
    if (g_commands_loaded)
    {
        return;
    }

    UINT32 count = hyperdbg_u_get_commands_count();
    if (count == 0)
    {
        // Try to force initialization by running a no-op command
        // Not strictly necessary; library side ensures initialization
    }

    g_all_commands.clear();
    g_all_commands.reserve(count);

    for (UINT32 i = 0; i < count; ++i)
    {
        char buf[128] = {0};
        if (hyperdbg_u_get_command_name_by_index(i, buf, (UINT32)sizeof(buf)))
        {
            g_all_commands.emplace_back(buf);
        }
    }

    g_commands_loaded = true;
}

static vector<string> get_prefix_matches(const string & prefix)
{
    vector<string> matches;
    if (!g_commands_loaded)
    {
        ensure_command_list_loaded();
    }

    string pfx = to_lower_copy(prefix);
    for (const auto & cmd : g_all_commands)
    {
        string low = to_lower_copy(cmd);
        if (low.rfind(pfx, 0) == 0) // starts_with
        {
            matches.push_back(cmd);
        }
    }
    return matches;
}

static string longest_common_prefix(const vector<string> & items)
{
    if (items.empty())
    {
        return string();
    }
    string lcp = items[0];
    for (size_t i = 1; i < items.size(); ++i)
    {
        const string & s = items[i];
        size_t         j = 0;
        while (j < lcp.size() && j < s.size() && tolower((unsigned char)lcp[j]) == tolower((unsigned char)s[j]))
        {
            ++j;
        }
        lcp.resize(j);
        if (lcp.empty())
        {
            break;
        }
    }
    return lcp;
}

static void print_first_n_lines(const string & text, int n)
{
    istringstream iss(text);
    string        line;
    int           count = 0;
    while (count < n && std::getline(iss, line))
    {
        printf("%s\n", line.c_str());
        ++count;
    }
    if (iss.peek() != EOF)
    {
        printf("...\n");
    }
}

static void show_help_preview_for_command(const string & cmd, bool multiline_prompt)
{
    char help_cmd[256] = {0};
    sprintf_s(help_cmd, sizeof(help_cmd), ".help %s", cmd.c_str());

    g_captured_output.clear();
    hyperdbg_u_set_text_message_callback((PVOID)hyperdbg_capture_messages);
    hyperdbg_u_run_command((CHAR *)help_cmd);
    hyperdbg_u_unset_text_message_callback();

    if (!g_captured_output.empty())
    {
        printf("\n");
        print_first_n_lines(g_captured_output, 6);
        if (multiline_prompt)
        {
            printf("> ");
        }
        else
        {
            hyperdbg_u_show_signature();
        }
    }
}

static string read_line_interactive(bool multiline_prompt)
{
    string buf;

    while (true)
    {
        int ch = _getch();

        // Handle special prefix for function keys
        if (ch == 0 || ch == 224)
        {
            int ext = _getch();
            (void)ext; // Ignored for now
            continue;
        }

        if (ch == '\r' || ch == '\n')
        {
            printf("\n");
            return buf;
        }
        else if (ch == '\t')
        {
            // Tab for autocomplete (first token only)
            size_t space_pos = buf.find(' ');
            if (space_pos != string::npos)
            {
                // Don't autocomplete beyond the first token
                printf("\a");
                continue;
            }

            string prefix = buf;
            auto   matches = get_prefix_matches(prefix);

            if (matches.empty())
            {
                printf("\a");
                continue;
            }
            else if (matches.size() == 1)
            {
                const string & full = matches[0];
                if (full.size() > prefix.size())
                {
                    string add = full.substr(prefix.size());
                    printf("%s", add.c_str());
                    buf += add;
                }
                // add trailing space after full command
                printf(" ");
                buf += ' ';

                // Show brief help preview
                show_help_preview_for_command(full, multiline_prompt);
                // Reprint current buffer
                printf("%s", buf.c_str());
            }
            else
            {
                string lcp = longest_common_prefix(matches);
                if (lcp.size() > prefix.size())
                {
                    string add = lcp.substr(prefix.size());
                    printf("%s", add.c_str());
                    buf += add;
                }
                else
                {
                    // Print suggestions
                    printf("\n");
                    int col = 0;
                    for (size_t i = 0; i < matches.size(); ++i)
                    {
                        const string & m = matches[i];
                        printf("%-16s", m.c_str());
                        col++;
                        if (col >= 6)
                        {
                            printf("\n");
                            col = 0;
                        }
                    }
                    if (col != 0)
                    {
                        printf("\n");
                    }
                    if (multiline_prompt)
                    {
                        printf("> ");
                    }
                    else
                    {
                        hyperdbg_u_show_signature();
                    }
                    printf("%s", buf.c_str());
                }
            }
        }
        else if (ch == 8) // backspace
        {
            if (!buf.empty())
            {
                printf("\b \b");
                buf.pop_back();
            }
            else
            {
                printf("\a");
            }
        }
        else if (isprint(ch))
        {
            putchar(ch);
            buf.push_back((char)ch);
        }
        else if (ch == 3) // Ctrl+C
        {
            // Cancel current line
            printf("\n");
            return string();
        }
        else
        {
            // Ignore others
        }
    }
}

static string to_lower_copy(const string & s)
{
   string r = s;
   transform(r.begin(), r.end(), r.begin(), [](unsigned char c) { return (char)tolower(c); });
   return r;
}

static string basename_only(const string & path)
{
   size_t pos = path.find_last_of("/\\");
   if (pos == string::npos)
   {
       return path;
   }
   return path.substr(pos + 1);
}

static string strip_ext(const string & name)
{
   size_t dot = name.find_last_of('.');
   if (dot == string::npos)
   {
       return name;
   }
   return name.substr(0, dot);
}

static string tchar_to_utf8(const TCHAR * s)
{
#ifdef UNICODE
    if (!s)
    {
        return string();
    }
    int len = WideCharToMultiByte(CP_UTF8, 0, s, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0)
    {
        return string();
    }
    string out(len - 1, '\0');
    (void)WideCharToMultiByte(CP_UTF8, 0, s, -1, &out[0], len, nullptr, nullptr);
    return out;
#else
    return s ? string(s) : string();
#endif
}

static DWORD find_process_id_by_name(const string & name)
{
   string target = to_lower_copy(name);
   string target_base = to_lower_copy(strip_ext(basename_only(target)));

   HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
   if (snap == INVALID_HANDLE_VALUE)
   {
       return 0;
   }

   PROCESSENTRY32 pe = {0};
   pe.dwSize = sizeof(pe);

   if (Process32First(snap, &pe))
   {
       do
       {
#ifdef UNICODE
           string exe = to_lower_copy(tchar_to_utf8(pe.szExeFile));
#else
           string exe = to_lower_copy(pe.szExeFile);
#endif
           string exe_base = to_lower_copy(strip_ext(basename_only(exe)));
           if (exe_base == target_base)
           {
               CloseHandle(snap);
               return pe.th32ProcessID;
           }
       } while (Process32Next(snap, &pe));
   }

   CloseHandle(snap);
   return 0;
}

struct ModuleInfo
{
   unsigned long long base = 0;
   unsigned long long entry = 0;
   string path; // utf-8 best-effort from lm output
};

static vector<ModuleInfo> parse_lm_output_user_modules(const string & out)
{
   vector<ModuleInfo> mods;

   istringstream iss(out);
   string line;
   while (getline(iss, line))
   {
       // Trim leading spaces
       size_t i = 0;
       while (i < line.size() && isspace((unsigned char)line[i]))
           ++i;
       if (i >= line.size())
           continue;

       // Expect two 16-hex numbers at the beginning separated by whitespace or tabs
       if (i + 16 <= line.size())
       {
           bool ok = true;
           for (size_t k = 0; k < 16; ++k)
           {
               if (!isxdigit((unsigned char)line[i + k]))
               {
                   ok = false;
                   break;
               }
           }
           if (!ok)
               continue;

           // Parse first 16 hex
           string h1 = line.substr(i, 16);
           size_t j = i + 16;
           // Skip whitespace
           while (j < line.size() && isspace((unsigned char)line[j]))
               ++j;

           // Parse second 16 hex
           if (j + 16 > line.size())
               continue;
           for (size_t k = 0; k < 16; ++k)
           {
               if (!isxdigit((unsigned char)line[j + k]))
               {
                   ok = false;
                   break;
               }
           }
           if (!ok)
               continue;

           string h2 = line.substr(j, 16);
           size_t p = j + 16;
           while (p < line.size() && isspace((unsigned char)line[p]))
               ++p;

           ModuleInfo mi;
           mi.base = strtoull(h1.c_str(), nullptr, 16);
           mi.entry = strtoull(h2.c_str(), nullptr, 16);
           if (p < line.size())
           {
               mi.path = line.substr(p);
           }
           mods.push_back(mi);
       }
   }

   return mods;
}

static bool hexdump(const unsigned char * buf, size_t size, unsigned long long start_addr)
{
   for (size_t i = 0; i < size; i += 16)
   {
       printf("%016llx  ", (unsigned long long)(start_addr + i));
       // hex bytes
       for (size_t j = 0; j < 16; ++j)
       {
           if (i + j < size)
               printf("%02X ", buf[i + j]);
           else
               printf("   ");
       }
       printf(" ");
       // ascii
       for (size_t j = 0; j < 16; ++j)
       {
           if (i + j < size)
           {
               unsigned char c = buf[i + j];
               if (isprint(c))
                   printf("%c", c);
               else
                   printf(".");
           }
       }
       printf("\n");
   }
   return true;
}

static int auto_kmemread_flow(const char * process_name,
                             const char * module_filter,
                             unsigned long long offset,
                             unsigned int size)
{
   // Load VMM and switch to local VMI mode
   if (hyperdbg_u_load_vmm() != 0)
   {
       printf("err, failed to load HyperDbg VMM. Make sure you run as Administrator and VT-x is enabled.\n");
       return 1;
   }

   hyperdbg_u_connect_local_debugger();

   DWORD pid = find_process_id_by_name(process_name);
   if (pid == 0)
   {
       printf("err, process '%s' not found.\n", process_name);
       return 1;
   }

   printf("Target process: %s (pid: 0x%X / %u)\n", process_name, pid, pid);

   // List user-mode modules via kernel (lm um pid <pid>)
   char cmd[128] = {0};
   sprintf_s(cmd, sizeof(cmd), "lm um pid %x", pid);

   g_captured_output.clear();
   hyperdbg_u_set_text_message_callback((PVOID)hyperdbg_capture_messages);
   hyperdbg_u_run_command((CHAR *)cmd);
   hyperdbg_u_unset_text_message_callback();

   vector<ModuleInfo> mods = parse_lm_output_user_modules(g_captured_output);
   if (mods.empty())
   {
       printf("warn, failed to enumerate modules via kernel.\n");
   }
   else
   {
       printf("User modules (base, entry, path):\n");
       for (size_t i = 0; i < mods.size(); ++i)
       {
           printf("%016llx  %016llx  %s\n", mods[i].base, mods[i].entry, mods[i].path.c_str());
       }
   }

   // Choose module: main module (first) or by name filter
   unsigned long long chosen_base = 0;
   string chosen_path;
   if (module_filter && strlen(module_filter) > 0 && !mods.empty())
   {
       string mf = to_lower_copy(module_filter);
       for (auto & m : mods)
       {
           if (to_lower_copy(m.path).find(mf) != string::npos)
           {
               chosen_base = m.base;
               chosen_path = m.path;
               break;
           }
       }
       if (chosen_base == 0)
       {
           printf("warn, module filter '%s' not found; defaulting to main module.\n", module_filter);
       }
   }

   if (chosen_base == 0)
   {
       if (!mods.empty())
       {
           chosen_base = mods[0].base;
           chosen_path = mods[0].path;
       }
       else
       {
           // Fallback: if module list is empty, we cannot pick a base reliably
           printf("err, cannot determine module base to read.\n");
           return 1;
       }
   }

   unsigned long long target_addr = chosen_base + offset;
   printf("Reading memory at %016llx (module base %016llx + offset 0x%llx) from VMX root...\n",
          target_addr,
          chosen_base,
          offset);

   vector<unsigned char> buffer(size);
   UINT32 ret_len = 0;
   DEBUGGER_READ_MEMORY_ADDRESS_MODE addr_mode = DEBUGGER_READ_ADDRESS_MODE_64_BIT;

   BOOLEAN ok = hyperdbg_u_read_memory(target_addr,
                                       DEBUGGER_READ_VIRTUAL_ADDRESS,
                                       READ_FROM_VMX_ROOT,
                                       pid,
                                       size,
                                       FALSE,
                                       &addr_mode,
                                       buffer.data(),
                                       &ret_len);

   if (!ok)
   {
       printf("err, read memory failed.\n");
       return 1;
   }

   if (ret_len == 0)
   {
       printf("warn, zero bytes returned.\n");
       return 0;
   }

   hexdump(buffer.data(), ret_len, target_addr);

   return 0;
}

/**
* @brief CLI main function
*
* @param argc
* @param argv
* @return int
*/
int
main(int argc, char * argv[])
{
   BOOLEAN exit_from_debugger = FALSE;
   string  previous_command;
   BOOLEAN reset = FALSE;

   //
   // Set console output code page to UTF-8
   //
   SetConsoleOutputCP(CP_UTF8);

   printf("HyperDbg Debugger [version: %s, build: %s]\n", CompleteVersion, BuildVersion);
   printf("Please visit https://docs.hyperdbg.org for more information...\n");
   printf("HyperDbg is released under the GNU Public License v3 (GPLv3).\n\n");

   if (argc != 1)
   {
       //
       // User-passed arguments to the debugger
       //
       if (!strcmp(argv[1], "--script"))
       {
           //
           // Handle the script
           //
           hyperdbg_u_script_read_file_and_execute_commandline(argc, argv);
           return 0;
       }
       else if (!strcmp(argv[1], "--kmemread"))
       {
           // Syntax: --kmemread <process_name> [--module <module_name>] [--offset <hex>] [--size <dec_or_hex>]
           const char * process_name   = nullptr;
           const char * module_filter  = nullptr;
           unsigned long long offset   = 0;
           unsigned int       size     = 0x100;

           if (argc >= 3)
           {
               process_name = argv[2];
           }
           else
           {
               printf("usage: --kmemread <process_name> [--module <module_name>] [--offset <hex>] [--size <n>]\n");
               return 1;
           }

           for (int i = 3; i < argc; ++i)
           {
               if (!strcmp(argv[i], "--module") && i + 1 < argc)
               {
                   module_filter = argv[++i];
               }
               else if (!strcmp(argv[i], "--offset") && i + 1 < argc)
               {
                   const char * v = argv[++i];
                   if ((v[0] == '0' && (v[1] == 'x' || v[1] == 'X'))) {
                       offset = strtoull(v + 2, nullptr, 16);
                   } else {
                       offset = strtoull(v, nullptr, 16);
                   }
               }
               else if (!strcmp(argv[i], "--size") && i + 1 < argc)
               {
                   const char * v = argv[++i];
                   if ((v[0] == '0' && (v[1] == 'x' || v[1] == 'X'))) {
                       size = (unsigned int)strtoul(v + 2, nullptr, 16);
                   } else {
                       size = (unsigned int)strtoul(v, nullptr, 10);
                   }
               }
               else
               {
                   printf("warn, unknown argument: %s\n", argv[i]);
               }
           }

           return auto_kmemread_flow(process_name, module_filter, offset, size);
       }
       else
       {
           printf("err, invalid command line options passed to the HyperDbg!\n");
           printf("supported: --script, --kmemread\n");
           return 1;
       }
   }

   while (!exit_from_debugger)
   {
       hyperdbg_u_show_signature();

       string current_command = "";

       //
       // Clear multiline
       //
       reset = TRUE;

   GetMultiLinecCommand:

       string temp_command = "";

       temp_command = read_line_interactive(reset == FALSE);

       //
       // Check for multi-line commands
       //
       if (hyperdbg_u_check_multiline_command((CHAR *)temp_command.c_str(), reset) == TRUE)
       {
           //
           // It's a multi-line command
           //
           reset = FALSE;

           //
           // Save the command with a space separator
           //
           current_command += temp_command + "\n";

           //
           // Show a small signature
           //
           printf("> ");

           //
           // Get next command
           //
           goto GetMultiLinecCommand;
       }
       else
       {
           //
           // Reset for future commands
           //
           reset = TRUE;

           //
           // Either the multi-line is finished or it's a
           // single line command
           //
           current_command += temp_command;
       }

       if (!current_command.compare("") && hyperdbg_u_continue_previous_command())
       {
           //
           // Retry the previous command
           //
           current_command = previous_command;
       }
       else
       {
           //
           // Save previous command
           //
           previous_command = current_command;
       }

       INT CommandExecutionResult = hyperdbg_u_run_command((CHAR *)current_command.c_str());

       //
       // if the debugger encounters an exit state then the return will be 1
       //
       if (CommandExecutionResult == 1)
       {
           //
           // Exit from the debugger
           //
           exit_from_debugger = true;
       }
       if (CommandExecutionResult != 2)
       {
           printf("\n");
       }
   }

   return 0;
}
