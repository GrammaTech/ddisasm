

readelf -S $1 | grep '\[*\.' | awk 'NF==6{print "section('\''"$3"'\''," $4",'\''" $5"'\'')."}NF==5{print "section('\''"$2"'\''," $3",'\''" $4"'\'')."}' > $1.sections

readelf -s $1 |  awk '$2 ~ /^[0-9a-f]+$/{print "symbol('\''"$2"'\'',"$3",'\''"$4"'\'','\''" $5"'\'','\''"$8"'\'')."}' > $1.symbols



