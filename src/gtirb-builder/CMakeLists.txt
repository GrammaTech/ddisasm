add_library(gtirb_builder STATIC GtirbBuilder.cpp ElfReader.cpp)

target_link_libraries(gtirb_builder ${LIEF_LIBRARIES} ${Boost_LIBRARIES} gtirb)

target_include_directories(gtirb_builder PUBLIC ${LIEF_INCLUDE_DIRS})

# Handle warnings from LIEF
function(set_msvc_lief_options TARGET_NAME)
  # conversion from 'type1' to 'type2', signed/unsigned mismatch
  target_compile_options(${TARGET_NAME} PRIVATE -wd4245)

  # unary minus operator applied to unsigned type, result still unsigned
  target_compile_options(${TARGET_NAME} PRIVATE -wd4146)

  # conversion from 'size_t' to 'type', possible loss of data
  target_compile_options(${TARGET_NAME} PRIVATE -wd4267)

  # actual alignment (8) is greater than the  value specified in
  # __declspec(align())
  target_compile_options(${TARGET_NAME} PRIVATE -wd4359)
endfunction()

if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
  target_compile_definitions(gtirb_builder PRIVATE _CRT_SECURE_NO_WARNINGS)
  target_compile_definitions(gtirb_builder PRIVATE _CRT_NONSTDC_NO_WARNINGS)

  set_msvc_lief_options(gtirb_builder)
  set_common_msvc_options(gtirb_builder)
endif()
