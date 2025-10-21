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
#include <string>
#include <conio.h>
#include <iostream>
#include <vector>
#include <fstream>

#include "SDK/HyperDbgSdk.h"
#include "SDK/imports/user/HyperDbgLibImports.h"

using namespace std;

//
// Simple interactive line reader with history support (Up/Down arrows)
// It keeps the cursor at the end of line (no mid-line editing).
//
static string g_HistoryFilePath;

static string GetHistoryFilePath()
{
   CHAR appdata[MAX_PATH] = {0};
   DWORD len              = GetEnvironmentVariableA("APPDATA", appdata, MAX_PATH);

   string baseDir;
   if (len && len < MAX_PATH)
   {
       baseDir = string(appdata) + "\\HyperDbg";
   }
   else
   {
       baseDir = ".\\HyperDbg"; // fallback to current directory
   }

   CreateDirectoryA(baseDir.c_str(), NULL);
   string historyPath = baseDir + "\\history.txt";
   return historyPath;
}

static void LoadHistory(vector<string> & history)
{
   history.clear();

   if (g_HistoryFilePath.empty())
   {
       g_HistoryFilePath = GetHistoryFilePath();
   }

   ifstream in(g_HistoryFilePath);
   if (!in.is_open())
   {
       return;
   }

   string line;
   while (std::getline(in, line))
   {
       if (!line.empty())
       {
           history.push_back(line);
       }
   }
}

static void AppendHistory(const string & line)
{
   if (line.empty())
   {
       return;
   }

   if (g_HistoryFilePath.empty())
   {
       g_HistoryFilePath = GetHistoryFilePath();
   }

   ofstream out(g_HistoryFilePath, ios::app);
   if (!out.is_open())
   {
       return;
   }
   out << line << '\n';
}

static void RedrawCurrentBuffer(bool is_multiline, const char * multiline_prompt, const string & buffer, size_t lastPrintedLen)
{
   // Move to the beginning of the line
   cout << '\r';

   if (is_multiline)
   {
       cout << (multiline_prompt ? multiline_prompt : "> ");
   }
   else
   {
       // Reprint signature as prompt
       hyperdbg_u_show_signature();
   }

   // Print buffer and clear residual characters if any
   cout << buffer;

   if (lastPrintedLen > buffer.size())
   {
       size_t diff = lastPrintedLen - buffer.size();
       for (size_t i = 0; i < diff; ++i)
       {
           cout << ' ';
       }
       // Return again to start and print prompt + buffer to keep cursor at end of new buffer
       cout << '\r';
       if (is_multiline)
       {
           cout << (multiline_prompt ? multiline_prompt : "> ");
       }
       else
       {
           hyperdbg_u_show_signature();
       }
       cout << buffer;
   }

   cout.flush();
}

static string ReadLineInteractive(bool is_multiline, const char * multiline_prompt, const vector<string> & history)
{
   string buffer;
   size_t lastPrintedLen = 0;

   // History navigation index (starts past the last item)
   long long histIndex = static_cast<long long>(history.size());

   // If multiline, prompt is printed by caller. If not multiline, caller already printed signature.
   // Start reading characters until Enter is pressed.
   while (true)
   {
       int ch = _getch();

       // Handle special keys
       if (ch == 0 || ch == 224)
       {
           int second = _getch();
           if (second == 72) // Up arrow
           {
               if (histIndex > 0)
               {
                   histIndex--;
                   buffer = history[histIndex];
                   RedrawCurrentBuffer(is_multiline, multiline_prompt, buffer, lastPrintedLen);
                   lastPrintedLen = buffer.size();
               }
               continue;
           }
           else if (second == 80) // Down arrow
           {
               if (histIndex < static_cast<long long>(history.size()))
               {
                   histIndex++;
               }
               if (histIndex >= 0 && histIndex < static_cast<long long>(history.size()))
               {
                   buffer = history[histIndex];
               }
               else
               {
                   buffer.clear();
               }
               RedrawCurrentBuffer(is_multiline, multiline_prompt, buffer, lastPrintedLen);
               lastPrintedLen = buffer.size();
               continue;
           }
           else
           {
               // Ignore other special keys (Left/Right/Home/End)
               continue;
           }
       }

       // Enter key
       if (ch == '\r' || ch == '\n' || ch == 13)
       {
           cout << "\n";
           break;
       }

       // Backspace
       if (ch == 8)
       {
           if (!buffer.empty())
           {
               buffer.pop_back();
               // Erase last char visually
               cout << '\b' << ' ' << '\b';
               cout.flush();
               if (lastPrintedLen > 0)
               {
                   lastPrintedLen--;
               }
           }
           continue;
       }

       // Basic printable ASCII range
       if (ch >= 32 && ch <= 126)
       {
           buffer.push_back(static_cast<char>(ch));
           cout << static_cast<char>(ch);
           cout.flush();
           lastPrintedLen++;
           continue;
       }

       // Ignore other control characters
   }

   return buffer;
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

   //
   // Load persistent history
   //
   vector<string> history;
   LoadHistory(history);

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
       }
       else
       {
           printf("err, invalid command line options passed to the HyperDbg!\n");
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

       bool is_multiline_mode = false;

   GetMultiLinecCommand:

       string temp_command = "";

       // Read interactively with history support
       temp_command = ReadLineInteractive(is_multiline_mode, is_multiline_mode ? "> " : nullptr, history);

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
           // Enable multiline mode and show a small prompt for the next line
           //
           is_multiline_mode = true;
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
           // End multiline mode (if active) or single-line command
           //
           is_multiline_mode = false;
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

       //
       // Append to history (persist) if not empty
       //
       if (!current_command.empty())
       {
           history.push_back(current_command);
           AppendHistory(current_command);
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
