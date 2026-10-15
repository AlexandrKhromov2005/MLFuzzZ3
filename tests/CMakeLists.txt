add_subdirectory(unit)
add_subdirectory(cross)
add_subdirectory(fixtures)
add_subdirectory(runtime)
add_subdirectory(integration)

# Optional build layers must be reflected by the lint source selection.
add_test(NAME LintBuildGateRegression
  COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/regression/test-lint-build-gate.sh)
