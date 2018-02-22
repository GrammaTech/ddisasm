./reassemble_and_test.sh ../real_world_examples/grep-2.5.4 src/grep -lpcre
./reassemble_and_test.sh ../real_world_examples/gzip-1.2.4 gzip
./reassemble_and_test.sh ../real_world_examples/bar-1.11.0 bar
./reassemble_and_test.sh ../real_world_examples/conflict-6.0 conflict 
./reassemble_and_test.sh ../real_world_examples/ed-0.2/ ed
./reassemble_and_test.sh ../real_world_examples/ed-0.9/ ed
./reassemble_and_test.sh ../real_world_examples/marst-2.4/ marst
./reassemble_and_test.sh ../real_world_examples/units-1.85/ units -lm -lreadline -lncurses

./reassemble_and_test.sh ../real_world_examples/doschk-1.1/ doschk
./reassemble_and_test.sh ../real_world_examples/bool-0.2/ src/bool

./reassemble_and_test.sh ../real_world_examples/m4-1.4.4/ src/m4
./reassemble_and_test.sh ../real_world_examples/patch-2.6.1/ src/patch
./reassemble_and_test.sh ../real_world_examples/enscript-1.6.1/ src/enscript -lm
#hell yeah
./reassemble_and_test.sh ../real_world_examples/bison-2.1/ src/bison
./reassemble_and_test.sh ../real_world_examples/sed-4.2/ sed/sed
./reassemble_and_test.sh ../real_world_examples/tar-1.29/ src/tar


# almost
#./reassemble_and_test.sh ../real_world_examples/make-3.80/ make

#not even close
#./reassemble_and_test.sh ../real_world_examples/rsync-3.0.7/ rsync
#./reassemble_and_test.sh ../real_world_examples/flex-2.5.4/ flex
#./reassemble_and_test.sh ../real_world_examples/lighttpd-1.4.18/ src/lighttpd -lpcre -ldl

#./reassemble_and_test.sh ../real_world_examples/re2c-0.13.5/ re2c g++
#./reassemble_and_test.sh ../real_world_examples/gperf-3.0.3/ src/gperf  g++
