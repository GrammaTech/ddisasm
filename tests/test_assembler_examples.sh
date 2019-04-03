dir="../examples/asm_examples/"

examples=(
    "ex_pointerReatribution3 ex"
    "ex_pointerReatribution3_clang ex"
    "ex_pointerReatribution3_pie ex"
    "ex_relative_switch ex"
);

error=0
success=0
for ((i = 0; i < ${#examples[@]}; i++)); do
    echo "#Example $file in assembler"
    if !(./reassemble_and_test.sh -strip -stir $dir${examples[$i]}) then
       ((error++))
       else
       ((success++))
    fi
done

echo "$success/$((error+success)) tests succeed"

if (( $error > 0 )); then
    echo "$error tests failed"
    exit 1
fi
