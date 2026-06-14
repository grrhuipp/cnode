set(FILE "${PROJECT_SOURCE_DIR}/src/proxy/trojan/inbound/trojan_inbound.cpp")

if(NOT EXISTS "${FILE}")
    message(FATAL_ERROR "missing Trojan inbound implementation: ${FILE}")
endif()

file(READ "${FILE}" content)

string(FIND "${content}" "buf::MultiBuffer raw = co_await src_.ReadMultiBuffer();" raw_read_pos)
string(FIND "${content}" "raw.clear();" raw_clear_pos)
if(raw_read_pos EQUAL -1 OR raw_clear_pos EQUAL -1 OR raw_clear_pos LESS raw_read_pos)
    message(FATAL_ERROR
        "Trojan UDP reader must release raw ReadMultiBuffer ownership after feeding the framer")
endif()

string(FIND "${content}" "class TrojanUdpWriter final" writer_pos)
string(FIND "${content}" "mb.clear();" writer_clear_pos)
string(FIND "${content}" "co_await dst_.WriteMultiBuffer(std::move(out));" writer_write_pos)
if(writer_pos EQUAL -1 OR writer_clear_pos EQUAL -1 OR writer_write_pos EQUAL -1 OR
   writer_clear_pos LESS writer_pos OR writer_write_pos LESS writer_clear_pos)
    message(FATAL_ERROR
        "Trojan UDP writer must release input MultiBuffer before awaiting encoded output write")
endif()
