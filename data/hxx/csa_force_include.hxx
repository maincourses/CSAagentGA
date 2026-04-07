#pragma once

#if defined(__has_include)
#    if __has_include("gme/base/importexport.h")
#        include "gme/base/importexport.h"
#    endif
#endif

// CSA-only: neutralize dllimport/dllexport to avoid linkage diagnostics
// on internal/anonymous-namespace helper types.
#undef EXPORT_SYMBOL
#undef IMPORT_SYMBOL
#define EXPORT_SYMBOL
#define IMPORT_SYMBOL

#if defined(__has_include)
#    if __has_include(<concepts>)
#        include <concepts>
#    endif
#    if __has_include(<cstdint>)
#        include <cstdint>
#    endif
#    if __has_include(<fstream>)
#        include <fstream>
#    endif
#    if __has_include(<format>)
#        include <format>
#    endif
#    if __has_include(<iostream>)
#        include <iostream>
#    endif
#    if __has_include(<optional>)
#        include <optional>
#    endif
#    if __has_include(<sstream>)
#        include <sstream>
#    endif
#    if __has_include(<stdexcept>)
#        include <stdexcept>
#    endif
#    if __has_include(<string>)
#        include <string>
#    endif
#    if __has_include(<type_traits>)
#        include <type_traits>
#    endif
#endif

#if defined(__has_include)
#    if __has_include("gme/kernel/ag_spline.hxx")
#        include "gme/kernel/ag_spline.hxx"
#    endif
#endif
