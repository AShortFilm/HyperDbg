/**
 * @file HyperEvade.h
 * @author HyperDbg Project
 * @brief Declarations for hyperevade interface wrappers
 * @details
 *
 * @version 0.1
 * @date 2025-06-07
 *
 * @copyright This project is released under the GNU Public License v3.
 *
 */
#pragma once

#include "SDK/headers/RequestStructures.h"

BOOLEAN
TransparentHideDebuggerWrapper(DEBUGGER_HIDE_AND_TRANSPARENT_DEBUGGER_MODE * TransparentModeRequest);

BOOLEAN
TransparentUnhideDebuggerWrapper(DEBUGGER_HIDE_AND_TRANSPARENT_DEBUGGER_MODE * TransparentModeRequest);

BOOLEAN
TransparentEnableDefaultMode();
