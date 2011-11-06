#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import argparse
import logging
import sys
from collections import defaultdict

from haystack.reverse import utils

def make(opts):
fname = opts.gexf
import networkx
graph=networkx.readwrite.gexf.read_gexf(  '../../outputs/skype.1.a.gexf')
#dg = graph.to_directed()

isolates = networkx.algorithms.isolate.isolates(graph)
graph.remove_nodes_from(isolates)
subgraphs = networkx.algorithms.components.connected.connected_component_subgraphs(graph)
isolates1 = set( utils.flatten( g.nodes() for g in subgraphs if len(g) == 1) ) # self connected
isolates2 = set( utils.flatten( g.nodes() for g in subgraphs if len(g) == 2) ) 
isolates3 = set( utils.flatten( g.nodes() for g in subgraphs if len(g) == 3) ) 

graph.remove_nodes_from(isolates1)
graph.remove_nodes_from(isolates2)
graph.remove_nodes_from(isolates3)

subgraphs = networkx.algorithms.components.connected.connected_component_subgraphs(graph)

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
        print 'numNodes ', numNodes, 'graphs',g1,g2, ' isomorphic'
        isoGraph.add_edge(g1,g2, {'isomorphic':True})
        if g2 in todo:  todo.remove(g2) 
        if g1 in todo:  todo.remove(g1) 
        break # we can stop here, chain comparaison will work between g2 and g3
  # check non isomorphic between them
  todo2 = set(todo)
  for i,g1 in enumerate(todo):
    for g2 in todo[i+1:]:
      if networkx.is_isomorphic(g1, g2):
        print 'todo numNodes ', numNodes, 'graphs',i,i+1, ' isomorphic'
        isoGraph.add_edge(g1, g2, {'isomorphic':True})
        todo2.remove(g2)
        if g1 in todo:  todo2.remove(g1)
        break # we can stop here, chain comparaison will work between g2 and g3
  # check non isomorphic with already existing 
  # last duplicate chance
  todo2 = set(todo)
    
  if len(isoGraph) > 0:
    isoGraphs[numNodes] = isoGraph

# draw the isomorphisms
for i,item in enumerate(isoGraphs.items()):
  num,g = item
  for rg in g.nodes():
    networkx.draw(rg)
  fname = os.path.sep.join([Config.imgCacheDir, 'isomorph_subgraphs_%d.png'%(num) ] )
  plt.savefig(fname)
  plt.clf()
# neef to use gephi-like for rendering nicely on the same pic

# draw the figs
for i,g in enumerate(subgraphs[1:100]):
  networkx.draw(g.to_directed())
  fname = os.path.sep.join([Config.imgCacheDir, 'subgraph_%d.png'%(i) ] )
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
  
  flog = os.path.sep.join([Config.cacheDir,'log'])
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
