SECTIONS {
  .gcc_except_table : { *(.gcc_except_table) }
}
INSERT BEFORE .note.gnu.build-id;
