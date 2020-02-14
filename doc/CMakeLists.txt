find_program(
  PANDOC pandoc
  HINTS $ENV{PATH}
  DOC "pandoc must be in your PATH to build documentation.")
find_program(
  GZIP gzip
  HINTS $ENV{PATH}
  DOC "gzip must be in your PATH to build documentation.")
if(NOT PANDOC)
  message(
    WARNING "pandoc was not found in your PATH. Unable to build documentation.")
elseif(NOT GZIP)
  message(
    WARNING "gzip was not found in your PATH. Unable to build documentation.")
else()
  set(MANUAL_MD "${CMAKE_CURRENT_SOURCE_DIR}/ddisasm.md")
  set(MANUAL_HTML "${CMAKE_BINARY_DIR}/doc/ddisasm.html")
  set(MANUAL_MAN "${CMAKE_BINARY_DIR}/doc/ddisasm.md.tmp")
  set(MANUAL_MAN_GZ "${CMAKE_BINARY_DIR}/doc/ddisasm.1.gz")

  add_custom_command(
    OUTPUT ${MANUAL_HTML}
    COMMAND
      ${PANDOC} -s -t html ${MANUAL_MD} -o ${MANUAL_HTML}
    DEPENDS ${MANUAL_MD})
  add_custom_command(
    OUTPUT ${MANUAL_MAN}
    COMMAND
      ${PANDOC} -s -t man ${MANUAL_MD} -o ${MANUAL_MAN}
    DEPENDS ${MANUAL_MD})
  add_custom_command(
    OUTPUT ${MANUAL_MAN_GZ}
    COMMAND ${GZIP} -9 < ${MANUAL_MAN} -> ${MANUAL_MAN_GZ}
    DEPENDS ${MANUAL_MAN})

  add_custom_target(
    doc
    DEPENDS ${MANUAL_HTML}
    DEPENDS ${MANUAL_MAN_GZ})
endif()
