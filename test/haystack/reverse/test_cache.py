
#
#
# this should test the memoryleaks...
#
#
#

from __future__ import print_function

def main():
    from haystack.reverse import context
    ctx = context.get_context('test/dumps/skype/skype.1/skype.1.f')
    from haystack.reverse import structure
    it = structure.cache_load_all_lazy(ctx)

    structs = []
    for i in range(10000):
        structs.append(it.next())

    [s.to_string() for addr, s in structs]

    # 51 Mo

    structure.CacheWrapper.refs.size = 5
    for i in range(5):
        structure.CacheWrapper.refs[i] = i

    # 51 Mo

    from meliae import scanner
    scanner.dump_all_objects('filename.json')

    from meliae import loader
    om = loader.load('filename.json')
    s = om.summarize()
    s
    '''
  Total 206750 objects, 150 types, Total size = 27.2MiB (28495037 bytes)
   Index   Count   %      Size   % Cum     Max Kind
       0   75801  36   7529074  26  26   27683 str
       1   11507   5   6351864  22  48     552 Field
       2      16   0   5926913  20  69 2653328 numpy.ndarray
       3   10000   4   1680000   5  75     168 CacheWrapper
       4    2099   1   1158648   4  79     552 AnonymousStructInstance
       5    1182   0    857136   3  82   98440 dict
       6   18630   9    745200   2  85      40 weakref
       7   14136   6    633148   2  87   43812 list
  '''
    # clearly Field instances keep some place....
    # most 10000 Anonymous intances are not int memory now

    om.compute_referrers()

    # om[ addr].parents
    # om[ addr].children

    # get the biggest Field
    f_addr = s.summaries[1].max_address
    om[f_addr]

    # Field(179830860 552B 21refs 1par)

    om[f_addr].parents
    # [179834316]
    # >>> om[ 179834316 ]
    # list(179834316 132B 19refs 1par)  <- list of fields in Struct

    l_addr = om[f_addr].parents[0]
    om[l_addr].parents
    # [179849516]
    # >>> om[ 179849516 ]
    # AnonymousStructInstance(179849516 552B 23refs 19par)

    anon_addr = om[l_addr].parents[0]
    om[anon_addr]
    # 179849516 is a anon struct
    import networkx
    import matplotlib.pyplot as plt

    graphme()


def n(o):
    return str(o).split(' ')[0]


def stop(o):
    s = n(om[o])
    if s.startswith('classobj') or s.startswith('func'):
        return True
    if s.startswith('module') or s.startswith('local'):
        return True
    return False


def rec_add_child(graph, knowns, addr, t=''):
    for c in om[addr].children:
        if stop(c):
            return
        graph.add_edge(n(om[addr]), n(om[c]))
        childscount = len(om[c].children)
        print('c:', c, 'has', childscount, 'children')
        if childscount > 0:
            print(om[c])
        # add rec
        if c in knowns:
            return
        knowns.add(c)
        rec_add_child(graph, knowns, c, t + '\t')
        rec_add_parent(graph, knowns, c, t + '\t')


def rec_add_parent(graph, knowns, addr, t=''):
    for p in om[addr].parents:
        if stop(p):
            return
        graph.add_edge(n(om[p]), n(om[addr]))
        childscount = len(om[p].parents)
        print('p:', p, 'has', childscount, 'parents')
        if childscount > 0:
            print(om[p])
        # add rec
        if p in knowns:
            return
        knowns.add(p)
        rec_add_parent(graph, knowns, p, t + '\t')
        rec_add_child(graph, knowns, p, t + '\t')


def graphme():
    mygraph = networkx.DiGraph()
    addr = anon_addr
    known = set()
    known.add(addr)

    rec_add_child(mygraph, known, addr)

    known = set()
    known.add(addr)
    rec_add_parent(mygraph, known, addr)

    #pos = networkx.spring_layout(mygraph)
    # networkx.draw(mygraph,pos)

    # plt.show()
    networkx.readwrite.gexf.write_gexf(mygraph, 'test.gexf')
