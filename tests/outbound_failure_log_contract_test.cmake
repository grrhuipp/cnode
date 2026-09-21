if(NOT DEFINED SOURCE_DIR)
    message(FATAL_ERROR "SOURCE_DIR is required")
endif()

file(READ
    "${SOURCE_DIR}/src/proxy/freedom/freedom_outbound.cpp"
    FREEDOM_OUTBOUND_SOURCE)
file(READ
    "${SOURCE_DIR}/src/app/dispatcher/default_dispatcher.cpp"
    DISPATCHER_SOURCE)

if(FREEDOM_OUTBOUND_SOURCE MATCHES
       "LOG_CONN_WARN[(]ctx, \"failed to dial")
    message(FATAL_ERROR
        "freedom dial failures must not duplicate the dispatcher warning")
endif()

string(REGEX MATCHALL
       "LOG_CONN_DEBUG[(]ctx, \"failed to dial UDP"
       UDP_DIAL_DEBUG_LOGS
       "${FREEDOM_OUTBOUND_SOURCE}")
list(LENGTH UDP_DIAL_DEBUG_LOGS UDP_DIAL_DEBUG_LOG_COUNT)
if(NOT UDP_DIAL_DEBUG_LOG_COUNT EQUAL 2)
    message(FATAL_ERROR
        "both freedom UDP dial failure causes must remain available at debug level")
endif()

if(NOT FREEDOM_OUTBOUND_SOURCE MATCHES
       "LOG_CONN_DEBUG[(]ctx, \"failed to dial \{\}" OR
   NOT DISPATCHER_SOURCE MATCHES
       "LOG_CONN_WARN[(]ctx, \"failed to process outbound traffic")
    message(FATAL_ERROR
        "dispatcher must own the terminal warning while freedom preserves debug detail")
endif()
