tarballs=(
    "gzip-1.2.4.tar.gz" 
    "bar-1.11.0.tar.gz"
    "conflict-6.0.tar.gz"
    "ed-0.2.tar.gz"
    "marst-2.4.tar.gz"
    "units-1.85.tar.gz"
    "doschk-1.1.tar.gz"
    "bool-0.2.tar.gz"
    "m4-1.4.4.tar.gz"
    "patch-2.6.1.tar.gz"
    "enscript-1.6.1.tar.gz"
    "bison-2.1.tar.gz"
    "sed-4.2.tar.gz"
    "flex-2.5.4.tar.gz"
    "make-3.80.tar.gz"
    "rsync-3.0.7.tar.gz"
    "gperf-3.0.3.tar.gz"
    "re2c-0.13.5.tar.gz"
    "lighttpd-1.4.18.tar.gz"
    "tar-1.29.tar.gz"
);
tarballs_bz2=(
    "grep-2.5.4.tar.bz2"
    "ed-0.9.tar.bz2"
);

dir="../real_world_examples"

rm -rf $dir
mkdir $dir

for tarball in  "${tarballs[@]}"; do
#   cp /u4/TARBALLS/codesonar-tests/$tarball $dir
    tar xvzf /u4/TARBALLS/codesonar-tests/$tarball -C $dir
done

for tarball in  "${tarballs_bz2[@]}"; do
#   cp /u4/TARBALLS/codesonar-tests/$tarball $dir
    tar xvjf /u4/TARBALLS/codesonar-tests/$tarball -C $dir
done
