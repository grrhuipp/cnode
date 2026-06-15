file(READ "${PROJECT_SOURCE_DIR}/include/acppnode/app/worker.hpp" worker_header)
file(READ "${PROJECT_SOURCE_DIR}/src/app/worker.cpp" worker_cpp)

if(worker_header MATCHES "InitRouter[\\s\\S]*PreparedOutboundConfig")
    message(FATAL_ERROR
        "Worker InitRouter declaration must not depend on prepared outbound lists; pass the default outbound tag instead")
endif()

if(worker_cpp MATCHES "InitRouter[ \t\r\n]*\\([^\\)]*runtime_snapshot->outbounds")
    message(FATAL_ERROR
        "Worker must not pass prepared outbound lists into InitRouter")
endif()

if(NOT worker_cpp MATCHES "default_outbound_tag" OR
   NOT worker_cpp MATCHES "runtime_snapshot->default_outbound_tag")
    message(FATAL_ERROR
        "Worker must use the normalized Router default outbound tag before calling InitRouter")
endif()

if(NOT worker_cpp MATCHES "router(\\.|->)Configure[ \t\r\n]*\\([ \t\r\n]*routing,[ \t\r\n]*default_outbound_tag")
    message(FATAL_ERROR
        "Worker InitRouter must delegate routing construction with an explicit default outbound tag")
endif()
