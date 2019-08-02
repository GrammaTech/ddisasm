diff=$(diff out.txt /tmp/res.txt)
if [[ -z  $diff ]] ; then
    echo "TEST OK";
else
    echo "TEST FAILED"
    echo "$diff"
    exit 1
fi
