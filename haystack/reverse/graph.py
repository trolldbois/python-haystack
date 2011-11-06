#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import argparse
import logging
import os
import sys
from collections import defaultdict

from haystack import config
from haystack.reverse import utils


# extract graph 
def depthSubgraph(source, target, nodes, depth):
  if depth == 0:
    return
  depth-=1
  for node in nodes:
    neighbors = source.neighbors(node)
    target.add_edges_from( source.edges(node) )
    depthSubgraph(source, target, neighbors, depth)
  return 

def make(opts):
fname = opts.gexf

import reversers
from reversers import *  # by the pickle of my thumb
context = reversers.getContext('../../outputs/skype.1.a')

import networkx
import matplotlib.pyplot as plt

digraph=networkx.readwrite.gexf.read_gexf(  '../../outputs/skype.1.a.gexf')

# clean solos
isolates = networkx.algorithms.isolate.isolates(graph)
digraph.remove_nodes_from(isolates)

# clean solos clusters
graph = digraph.to_undirected()
subgraphs = networkx.algorithms.components.connected.connected_component_subgraphs(graph)
isolates1 = set( utils.flatten( g.nodes() for g in subgraphs if len(g) == 1) ) # self connected
isolates2 = set( utils.flatten( g.nodes() for g in subgraphs if len(g) == 2) ) 
isolates3 = set( utils.flatten( g.nodes() for g in subgraphs if len(g) == 3) ) 
digraph.remove_nodes_from(isolates1)
digraph.remove_nodes_from(isolates2)
digraph.remove_nodes_from(isolates3)

#
#graph = digraph.to_undirected()
#subgraphs = networkx.algorithms.components.connected.connected_component_subgraphs(graph)
subgraphs = [g for g in subgraphs if len(g)>3]
isolatedGraphs = subgraphs[1:100]


# group by nodes number
isoDict = defaultdict(list)
[isoDict[len(g)].append(g) for g in isolatedGraphs]

# test isomorphism
isoGraphs = dict()
for numNodes, graphs in isoDict.items():
  numgraphs = len(graphs)
  if numgraphs == 1:
    continue
  isoGraph = networkx.Graph()
  # quick find isomorphisms
  todo = set(graphs)
  for i,g1 in enumerate(graphs):
    for g2 in graphs[i+1:]:
      if networkx.is_isomorphic(g1, g2):
        print 'numNodes:%d graphs %d, %d are isomorphic'%(numNodes, i, i+1)
        isoGraph.add_edge(g1,g2, {'isomorphic':True})
        if g2 in todo:  todo.remove(g2) 
        if g1 in todo:  todo.remove(g1) 
        break # we can stop here, chain comparaison will work between g2 and g3
    
  if len(isoGraph) > 0:
    isoGraphs[numNodes] = isoGraph

# draw the isomorphisms
for i,item in enumerate(isoGraphs.items()):
  num,g = item
  #networkx.draw(g)
  for rg in g.nodes():
    networkx.draw(rg)
  fname = os.path.sep.join([config.Config.imgCacheDir, 'isomorph_subgraphs_%d.png'%(num) ] )
  plt.savefig(fname)
  plt.clf()
# need to use gephi-like for rendering nicely on the same pic


bigGraph = networkx.DiGraph()
bigGraph.add_edges_from( subgraphs[0].edges() )

stack_addrs = utils.int_array_cache( config.Config.getCacheFilename(config.Config.CACHE_STACK_VALUES, context.dumpname)) 
stack_addrs_txt = set(['%x'%(addr) for addr in stack_addrs]) # new, no long

stacknodes = list(set(bigGraph.nodes()) & stack_addrs_txt)
print 'stacknodes left',len(stacknodes)
orig = list(set(graph.nodes()) & stack_addrs_txt)
print 'stacknodes orig',len(orig)

# identify strongly referenced structures
degreesDict = bigGraph.in_degree(bigGraph.nodes())
degreesList = [ (in_degree,node)  for node, in_degree in degreesDict.items() ]
degreesList.sort(reverse=True)

##### important struct
import structure
nb, saddr = degreesList[0]
s1 = structure.cacheLoad(context, int(saddr,16))
s1.decodeFields()
print s1.toString()

impDiGraph = networkx.DiGraph()
depthSubgraph(bigGraph, impDiGraph, [saddr], 1 )
print 'important struct with %d in_degree'%nb
fname = os.path.sep.join([config.Config.imgCacheDir, 'important_%s.png'%(saddr) ] )
networkx.draw(impDiGraph)
plt.savefig(fname)
plt.clf()

for node in impDiGraph.neighbors(saddr):
  st = structure.cacheLoad(context, int(node[:-1],16)) ## XXX change to -L
  st.decodeFields()
  st.pointerResolved=True
  st._aggregateFields()
  print st.getSignature(text=True)


#s1._aggregateFields()

s2 = utils.nextStructure(context, s1)
#s2b should start with \x00's



newgraph = bigGraph.subgraph(stacknodes)
newgraph.edges()

fname = os.path.sep.join([config.Config.imgCacheDir, 'newgraph.png' ] )

networkx.draw(newgraph.to_directed())

pos=networkx.graphviz_layout(newgraph)
networkx.draw_networkx_nodes(newgraph,pos)
networkx.draw_networkx_edges(newgraph,pos)
networkx.draw_networkx_labels(newgraph,pos, labels=labels)

plt.savefig(fname)
plt.clf()

newgraph = networkx.algorithms.components.connected.connected_component_subgraphs(newgraph)[0]

networkx.readwrite.gexf.write_gexf( newgraph, '../../outputs/skype.1.a.newgraph.gexf')

networkx.draw(newgraph.to_directed())
plt.savefig(fname)
plt.clf()



if False: # not that interesting
  ### take isdoGraphs[5] , 5 structs chains, and print them
  ind = 5
  g5 = isoGraphs[ind]
  g5subg = networkx.algorithms.components.connected.connected_component_subgraphs(g5)

  for group in g5subg:
    for structGraph in group.nodes():
      for saddr in structGraph.nodes():
        addr = int(saddr)
        struct = context.structures[addr]
        struct.decodeFields()
        sig = struct.getSignature(text=True)
        structGraph.node[saddr]['label'] = sig  # pretty tagging


  # draw the isomorphisms
  newgraph = networkx.Graph()
  for rg in g5.nodes():
    newgraph.add_nodes_from(rg.nodes(data=True))
    newgraph.add_edges_from(rg.edges(data=True))

  pos=networkx.graphviz_layout(newgraph)
  #networkx.draw_networkx_nodes(newgraph,pos)
  networkx.draw_networkx_edges(newgraph,pos)
  labels = dict([ (l, d['label']) for l, d in newgraph.node.items() ])
  networkx.draw_networkx_labels(newgraph,pos, labels=labels)
  #networkx.draw(rg)

  fname = os.path.sep.join([config.Config.imgCacheDir, 'isomorph_subgraphs_%d.png'%(ind) ] )
  plt.savefig(fname)
  plt.clf()


# draw the figs
for i,g in enumerate(isolatedGraphs):
  networkx.draw(g.to_directed())
  fname = os.path.sep.join([config.Config.imgCacheDir, 'subgraph_%d.png'%(i) ] )
  plt.savefig(fname)
  plt.clf()


networkx.draw()
import matplotlib.pyplot as plt
plt.show()
#networkx.algorithms.components.weakly_connected.weakly_connected_component_subgraphs(subg)


def argparser():
  rootparser = argparse.ArgumentParser(prog='haystack-reversers-graph', description='Play with graph repr of pointers relationships.')
  rootparser.add_argument('--debug', action='store_true', help='Debug mode on.')
  rootparser.add_argument('gexf', type=argparse.FileType('rb'), action='store', help='Source gexf.')
  rootparser.set_defaults(func=make)  
  return rootparser

def main(argv):
  parser = argparser()
  opts = parser.parse_args(argv)

  level=logging.INFO
  if opts.debug :
    level=logging.DEBUG
  
  flog = os.path.sep.join([config.Config.cacheDir,'log'])
  logging.basicConfig(level=level, filename=flog, filemode='w')
  
  #logging.getLogger('haystack').setLevel(logging.INFO)
  #logging.getLogger('dumper').setLevel(logging.INFO)
  #logging.getLogger('structure').setLevel(logging.INFO)
  #logging.getLogger('field').setLevel(logging.INFO)
  #logging.getLogger('progressive').setLevel(logging.INFO)
  logging.getLogger('graph').addHandler(logging.StreamHandler(stream=sys.stdout))

  log.info('[+] output log to %s'% flog)

  opts.func(opts)


if __name__ == '__main__':
  main(sys.argv[1:])
