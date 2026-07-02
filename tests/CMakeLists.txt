# ---------------------------------------------------------------------------
# tests/ — one CTest executable per test_*.c, each linking the parent
# `bonsai_chain` target + a `test_helpers` object lib (tests/helpers/*.c).
#
# Labels (CTest): default `unit`; GENUINELY live-network tests (filename carries
# a `_live` marker, e.g. test_woc_live_*.c) -> `net` (excluded from the default
# run with `ctest -LE net`); names matching zk -> `zk`. NOTE: the offline woc
# tests (test_woc_client.c is fully mock_http_transport; test_woc_rate_limiter.c
# is a pure is_429 classifier) hit no network and run by default as `unit` — only
# an explicit `_live` opt-in marks a test `net`.
#
# This file is GLOB-driven and MUST configure cleanly when tests/ is empty
# (zero test_*.c, zero helpers) — every block is guarded so an empty glob is
# a no-op rather than an error.
# ---------------------------------------------------------------------------

# Vendored Unity (single-file framework). Compiled once into an object lib so
# every test executable shares one translation unit.
add_library(unity OBJECT
  ${CMAKE_CURRENT_SOURCE_DIR}/../third_party/unity/unity.c)
target_include_directories(unity PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/../third_party/unity)
# Unity's generic asserts trip -Wextra under -Werror; keep it quiet locally.
target_compile_options(unity PRIVATE -Wno-error)

# Include dirs every test sees: parent public headers, Unity, and the helpers
# (so test_*.c and helper .c can `#include "mock_chain_source.h"` etc.).
set(BONSAI_TEST_INCLUDES
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/../third_party/unity
  ${CMAKE_CURRENT_SOURCE_DIR}/helpers)

# --- test_helpers object lib (tests/helpers/*.c) ----------------------------
# May be empty for now: GLOB can return nothing, so only create the target when
# there is at least one source — an OBJECT library with no sources errors.
file(GLOB TEST_HELPER_SRC CONFIGURE_DEPENDS
  ${CMAKE_CURRENT_SOURCE_DIR}/helpers/*.c)
if(TEST_HELPER_SRC)
  add_library(test_helpers OBJECT ${TEST_HELPER_SRC})
  target_include_directories(test_helpers PUBLIC ${BONSAI_TEST_INCLUDES})
  target_link_libraries(test_helpers PUBLIC bonsai_chain)
endif()

# --- one executable per test_*.c --------------------------------------------
file(GLOB TEST_SRC CONFIGURE_DEPENDS
  ${CMAKE_CURRENT_SOURCE_DIR}/test_*.c)

# Guard: with zero test sources yet, do nothing. This is what lets an empty
# tests/ tree configure without error.
if(TEST_SRC)
  foreach(test_file ${TEST_SRC})
    get_filename_component(test_name ${test_file} NAME_WE)   # e.g. test_woc_client

    # Convention: test_*_golden.c are STANDALONE golden-integration harnesses
    # (own main(), print PASS/FAIL, no Unity). All other test_*.c are Unity-style.
    if(test_name MATCHES "_golden$")
      add_executable(${test_name} ${test_file})
    else()
      add_executable(${test_name} ${test_file}
        $<TARGET_OBJECTS:unity>)
    endif()
    target_include_directories(${test_name} PRIVATE ${BONSAI_TEST_INCLUDES})
    target_link_libraries(${test_name} PRIVATE bonsai_chain)

    # Fold in the helper object files when the helpers lib exists.
    if(TARGET test_helpers)
      target_sources(${test_name} PRIVATE $<TARGET_OBJECTS:test_helpers>)
    endif()

    # Run from the chain_c source root so relative paths (tests/golden/,
    # artifacts/, legal/) resolve the same way the standalone build does.
    add_test(NAME ${test_name} COMMAND ${test_name}
      WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

    # --- label selection (default `unit`) ---
    # `net`: GENUINELY live-network tests, opted in by a `_live` filename marker
    #        (e.g. test_woc_live_*.c) — excluded from the default run. The offline
    #        woc tests (mock_http_transport client + pure is_429 rate-limiter) do
    #        NOT match and so run by default as `unit`.
    # `zk` : Groth16/circom/snarkjs tests — gated paths.
    if(test_name MATCHES "_golden$")
      set_tests_properties(${test_name} PROPERTIES LABELS "golden")
    elseif(test_name MATCHES "_live(_|$)")
      set_tests_properties(${test_name} PROPERTIES LABELS "net")
    elseif(test_name MATCHES "zk")
      set_tests_properties(${test_name} PROPERTIES LABELS "zk")
    else()
      set_tests_properties(${test_name} PROPERTIES LABELS "unit")
    endif()
  endforeach()
endif()
