./reassemble_and_test.sh ../examples/ex1 ex
./reassemble_and_test.sh ../examples/ex_float ex
./reassemble_and_test.sh ../examples/ex_getoptlong/ ex
./reassemble_and_test.sh ../examples/ex_2modulesPIC/ ex
./reassemble_and_test.sh ../examples/ex_stat/ ex
./reassemble_and_test.sh ../examples/ex_unitialized_data/ ex
./reassemble_and_test.sh ../examples/ex_struct/ ex
./reassemble_and_test.sh ../examples/ex_fprintf/ ex
./reassemble_and_test.sh ../examples/ex_noreturn/ ex
./reassemble_and_test.sh ../examples/ex_switch/ ex

./reassemble_and_test.sh ../real_world_examples/grep-2.5.4 src/grep -lpcre
./reassemble_and_test.sh ../real_world_examples/gzip-1.2.4 gzip
./reassemble_and_test.sh ../real_world_examples/bar-1.11.0 bar
./reassemble_and_test.sh ../real_world_examples/conflict-6.0 conflict 
./reassemble_and_test.sh ../real_world_examples/ed-0.2/ ed
./reassemble_and_test.sh ../real_world_examples/ed-0.9/ ed
./reassemble_and_test.sh ../real_world_examples/marst-2.4/ marst
./reassemble_and_test.sh ../real_world_examples/units-1.85/ units -lm -lreadline -lncurses
