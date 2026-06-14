file(READ "${PROJECT_SOURCE_DIR}/src/service/controller/control.cpp" controller_control)

if(controller_control MATCHES "ContainsUser[ \t\r\n]*\\([ \t\r\n]*const[ \t\r\n]+std::vector[ \t\r\n]*<[ \t\r\n]*api::UserInfo" OR
   controller_control MATCHES "std::any_of[ \t\r\n]*\\([ \t\r\n]*users\\.begin\\([ \t\r\n]*\\)[ \t\r\n]*,[ \t\r\n]*users\\.end\\([ \t\r\n]*\\)")
    message(FATAL_ERROR
        "controller user diff must not scan the full user list for every user")
endif()

if(NOT controller_control MATCHES "using[ \t\r\n]+UserInfoSet[ \t\r\n]*=[ \t\r\n]*std::unordered_set" OR
   NOT controller_control MATCHES "BuildUserInfoSet" OR
   NOT controller_control MATCHES "new_set\\.contains" OR
   NOT controller_control MATCHES "old_set\\.contains")
    message(FATAL_ERROR
        "controller user diff must use hashed user sets for near-linear panel sync")
endif()
