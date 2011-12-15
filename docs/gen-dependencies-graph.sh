#!/bin/sh 


# Generate the raw dependencies.
sfood --internal ../haystack | grep -v '.py~'> ./raw.deps
# Generate the graph.
cat raw.deps | sfood-graph -p | dot -Tsvg -o haystack.svg

# Filter and cluster.
#cd ../haystack ; ls -1d * > ../docs/clusters
#cd ../docs
#cat raw.deps | grep -v test | sfood-cluster -f clusters > filt.deps
# Generate the graph.
#cat filt.deps | sfood-graph -p | dot -Tsvg -o haystack.svg


