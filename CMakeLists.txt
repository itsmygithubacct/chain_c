cmake_minimum_required(VERSION 3.16)
project(bonsai_chain_c C)

# ---------------------------------------------------------------------------
# bonsai_chain_c — a faithful, functional C port of the chain/ BSV layer.
#   real libs: libsecp256k1 (ECDSA), OpenSSL libcrypto (SHA/BIGNUM/AES),
#              libcurl (HTTPS to WhatsOnChain); vendored cJSON, RIPEMD160, Unity.
#   scrypt-ts contract locking scripts are reconstructed from artifacts/*.json;
#   ZK proving/verify shells out to circom/snarkjs (BONSAI_ENABLE_ZK).
# ---------------------------------------------------------------------------

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

option(BUILD_SHARED_LIBS    "Build libbonsai_chain as a shared lib"        OFF)
option(BONSAI_ENABLE_ZK     "Enable ZK paths (needs snarkjs/circom + bn254)" OFF)
option(BONSAI_BUILD_TESTS   "Build the Unity/CTest test suite"             ON)
option(BONSAI_BUILD_BINS    "Build the bin/ CLI executables"               ON)
option(BONSAI_ASAN          "Add -fsanitize=address,undefined (Debug)"     OFF)

add_compile_definitions(_GNU_SOURCE)
add_compile_options(-Wall -Wextra)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  add_compile_options(-O2)
endif()
if(BONSAI_ASAN)
  # Sanitizer (Debug) build. -fno-sanitize-recover=undefined makes UBSan ABORT on
  # the first finding instead of its default print-and-continue (exit 0), so CI
  # actually gates on UB. ASan already aborts. NOTE: hardening (FORTIFY/PIE) below
  # is intentionally NOT applied here — _FORTIFY_SOURCE and PIE interact badly with
  # ASan/UBSan, so the sanitizer config is kept clean.
  add_compile_options(-fsanitize=address,undefined -fno-sanitize-recover=undefined -g -O1)
  add_link_options(-fsanitize=address,undefined)
else()
  # ---------------------------------------------------------------------------
  # Hardening — NON-sanitized builds ONLY (guarded by `NOT BONSAI_ASAN`).
  # _FORTIFY_SOURCE and PIE can conflict with ASan/UBSan, so they must never reach
  # the sanitizer configuration above. Every flag is probed (check_c_compiler_flag
  # / check_linker_flag) so a toolchain that lacks one degrades cleanly instead of
  # failing the build.
  # ---------------------------------------------------------------------------
  include(CheckCCompilerFlag)

  # _FORTIFY_SOURCE needs an optimizing build to do anything (Release sets -O2
  # above); scope it to Release so a non-optimized non-asan build doesn't trip the
  # "_FORTIFY_SOURCE requires compiling with optimization" warning.
  add_compile_definitions($<$<CONFIG:Release>:_FORTIFY_SOURCE=2>)

  # Probed compile-time hardening (stack protections, CET/branch protection, and
  # format-string diagnostics).
  foreach(_hflag
      -fstack-protector-strong
      -fstack-clash-protection
      -fcf-protection
      -Wformat
      -Wformat-security)
    string(MAKE_C_IDENTIFIER "HAVE_CFLAG${_hflag}" _hvar)
    check_c_compiler_flag("${_hflag}" ${_hvar})
    if(${_hvar})
      add_compile_options("${_hflag}")
    endif()
  endforeach()

  # Position-independent executables (-fPIE / -pie) via the canonical CMake path
  # so -pie lands on executables only (never on a shared lib link).
  if(POLICY CMP0083)
    cmake_policy(SET CMP0083 NEW)
  endif()
  include(CheckPIESupported OPTIONAL RESULT_VARIABLE _have_check_pie)
  if(_have_check_pie)
    check_pie_supported(LANGUAGES C)
  endif()
  if(NOT DEFINED CMAKE_C_LINK_PIE_SUPPORTED OR CMAKE_C_LINK_PIE_SUPPORTED)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
  endif()

  # Full RELRO + immediate binding (GOT made read-only after startup).
  if(NOT CMAKE_VERSION VERSION_LESS 3.18)
    include(CheckLinkerFlag)
    foreach(_lflag "-Wl,-z,relro" "-Wl,-z,now")
      string(MAKE_C_IDENTIFIER "HAVE_LDFLAG${_lflag}" _lvar)
      check_linker_flag(C "${_lflag}" ${_lvar})
      if(${_lvar})
        add_link_options("${_lflag}")
      endif()
    endforeach()
  else()
    # check_linker_flag unavailable (<3.18); relro/now are standard GNU ld flags.
    add_link_options(-Wl,-z,relro -Wl,-z,now)
  endif()
endif()

# --- dependencies -----------------------------------------------------------
find_package(PkgConfig REQUIRED)
pkg_check_modules(SECP256K1 REQUIRED IMPORTED_TARGET libsecp256k1)
pkg_check_modules(CRYPTO    REQUIRED IMPORTED_TARGET libcrypto)
pkg_check_modules(CURL      REQUIRED IMPORTED_TARGET libcurl)

# --- vendored third-party ----------------------------------------------------
set(THIRD_PARTY_SRC
  third_party/cJSON/cJSON.c
  third_party/ripemd160/ripemd160.c
)
set(THIRD_PARTY_INC
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/cJSON
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/ripemd160
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/mimc7_consts
)

# --- core library: every src/**/*.c (GLOB so tiers drop in incrementally) ----
file(GLOB_RECURSE LIB_SRC CONFIGURE_DEPENDS
  ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)

add_library(bonsai_chain STATIC ${LIB_SRC} ${THIRD_PARTY_SRC})
target_include_directories(bonsai_chain PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${THIRD_PARTY_INC})
target_link_libraries(bonsai_chain PUBLIC
  PkgConfig::SECP256K1 PkgConfig::CRYPTO PkgConfig::CURL m pthread)
if(BONSAI_ENABLE_ZK)
  target_compile_definitions(bonsai_chain PUBLIC BONSAI_ENABLE_ZK=1)
endif()

# --- CLI binaries: one executable per bin/*_main.c ---------------------------
if(BONSAI_BUILD_BINS)
  file(GLOB BIN_MAINS CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/bin/*_main.c)
  foreach(main_src ${BIN_MAINS})
    get_filename_component(base ${main_src} NAME_WE)         # e.g. agentd_main
    string(REGEX REPLACE "_main$" "" exe ${base})            # -> agentd
    add_executable(${exe} ${main_src})
    target_link_libraries(${exe} PRIVATE bonsai_chain)
  endforeach()
endif()

# --- tests -------------------------------------------------------------------
if(BONSAI_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
