add_executable(scm_rights_helper
  scm_rights_helper.cpp
)

target_link_libraries(scm_rights_helper
  PRIVATE
    fuzzer::session
    fuzzer::warnings
)
