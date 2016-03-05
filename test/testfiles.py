# /bin/python
# -*- coding: utf-8 -*-

class TestDump(object):
    def __init__(self, dumpname):
        self.dumpname = dumpname
        self.known_heaps = []
        self.known_segments = []
        self.known_ucr = []


# 2015-08-18
# PEB is 0x7ffde000 says volatility
# search also gives 0x20080000 and 0x5d0d2000
zeus_1668_vmtoolsd_exe = TestDump('test/dumps/vol/zeus.vmem.1668.dump')
zeus_1668_vmtoolsd_exe.known_heaps = [(0x00150000, 0x100000), # k
                                      (0x00250000, 0x10000), # k
                                      # peb says missing 0x00260000 # null structure
                                      (0x003f0000, 0x10000), # k
                                      #Commit routine removal #(0x00730000, 0xc8000), # probably not a heap
                                      #Commit routine removal #(0x00860000, 0x300000), # probably not a heap
                                      (0x00b70000, 0x10000), # k
                                      # peb says missing 0x00b80000 # null structure
                                      (0x00ba0000, 0x10000), # k
                                      (0x01620000, 0x80000), # k
                                      # peb says missing 0x01aa0000 # null structure
                                      # peb says missing 0x01ae0000 # null structure
                                      # peb says missing 0x01b20000 # null structure
                                      # peb says missing 0x01b60000 # null structure
                                      # peb says missing 0x01880000 # null structure
                                      # peb says missing 0x01da0000 # null structure
                                      (0x01eb0000, 0x10000), # k
                                      (0x01ec0000, 0x100000), # k
                                      # (0x5d09d000, 0x97000), # probably not a heap bad segments no-sig
                                      # (0x769f7000, 0xb3000), # probably not a heap, bad segments no-sig
                                      (0x7f6f0000, 0x100000)] # probably not a heap

# 0x00730000
# .Entry._0._0.Size is 193
# .Flags is 9
# .ForceFlags is 9
# .ProcessHeapsListIndex = 0
# .UnusedUnCommittedRanges unmapped pointer
# .VirtualAllocdBlocks unmapped pointers
# .Segments unmapped pointers
# .FreeLists unmapped pointers
# .LockVariable is null
# .CommitRoutine is not null
# .FrontEndHeap: null,
# .FrontEndHeapType == 1

# 0x00860000
# .Entry._0._0.Size is 193
# .Flags is 9
# .ForceFlags is 9
# .ProcessHeapsListIndex = 0
# .UnusedUnCommittedRanges unmapped pointer
# .VirtualAllocdBlocks unmapped pointers
# .Segments unmapped pointers
# .FreeLists unmapped pointers
# .LockVariable is null
# .CommitRoutine is not null
# .FrontEndHeap: null,
# .FrontEndHeapType == 1

# 0x5d09d000
# .FrontEndHeapType == 1
# .FreeLists has valid pointers to to null records
# .LockVariable is set
# .FrontEndHeap: 0x00070688,

# 0x7f6f0000
# .FreeLists unmapped pointers
# .FrontEndHeap: null,
# .FrontEndHeapType == 0

# First Entry, Last Entry
zeus_1668_vmtoolsd_exe.known_segments = [(0x150680, 0x250000),
                                         (0x250680, 0x260000),
                                         (0x3f0680, 0x400000),
                                         #(), # 0x00670000-0x00738000
                                         #(), # 0x00860000-0x00b60000
                                         (0xb70680, 0xb80000),
                                         (0xba0680, 0xbb0000),
                                         (0x1120040, 0x1220000),
                                         (0x1620680, 0x16a0000),
                                         #(), # 0x01db0000-0x01eb0000
                                         (0x1eb0680, 0x1ec0000),
                                         (0x1ec0680, 0x1fc0000),
                                         (0x1fc0040, 0x20c0000),
                                         #(), # 0x00670000-0x00738000
                                         (0x7f6f0680, 0x7f7f0000)]

zeus_1668_vmtoolsd_exe.known_chunks = {#0x5d09d000: (0x0, 0x0),
                                       #0x769f7000: (0x0, 0x0),
                                       0x250000: (0x4fe0, 0x9a0),
                                       0x7f6f0000: (0x2988, 0x0),
                                       0x3f0000: (0x1d20, 0x0),
                                       0xb70000: (0x187e8, 0x158),
                                       0xba0000: (0x1ab0, 0x9ed0),
                                       0x1eb0000: (0x7600, 0x340),
                                       0x1ec0000: (0x1808, 0x178),
                                       0x1620000: (0x25e0, 0x3a0)}


# 2015-08-18 unverified
zeus_856_svchost_exe = TestDump('test/dumps/vol/zeus.vmem.856.dump')
zeus_856_svchost_exe.known_heaps = [(0x00090000, 0x100000),
                                    (0x00190000, 0x10000),
                                    (0x001a0000, 0x10000),
                                    (0x00350000, 0x10000),
                                    (0x003b0000, 0x10000),
                                    # (0x00460000, 0x10000), miscapture ?
                                    (0x00c30000, 0x80000),
                                    (0x00d60000, 0x10000),
                                    (0x00e20000, 0x10000),
                                    (0x00e80000, 0x10000),
                                    (0x7f6f0000, 0x100000)]

zeus_856_svchost_exe.known_records = [(0x992f0, 14720)]

# putty.1.dump is a win7 32 bits memory dump
putty_1_win7 = TestDump('test/dumps/putty/putty.1.dump')
putty_1_win7.known_heaps = [(0x00010000, 0x10000), # 64bits
                            (0x00300000, 0x29000), # 64bits
                            (0x00390000, 0x3000),
                            (0x00540000, 0x1000),
                            (0x00580000, 0x9000),
                            (0x005c0000, 0x59000),
                            (0x01ef0000, 0x1000),
                            (0x02010000, 0x21000),
                            (0x02080000, 0x10000),
                            (0x021f0000, 0x6000),
                            (0x03360000, 0x1000),
                            (0x04030000, 0x1000),
                            (0x04110000, 0x1000),
                            (0x041c0000, 0x1000),
                            (0x7efe0000, 0x5000), # 64bits
                            (0xfffff900c0580000, 0x3000), # kernel,session
                            (0xfffff900c0800000, 0xe0000), # kernel,session
                            # from free stuf - erroneous
                            #( 0x0061a000, 1200),
                            ]

# heap, ucr_start, ucr_end, ucr_size
putty_1_win7.known_ucr = {0x00010000: [(0x00012000, 0x00020000, 0xe000)], # 64 bits
                          0x00300000: [(0x00329000, 0x00380000, 0x57000)], # 64 bits
                          0x00390000: [(0x00393000, 0x003a0000, 0xd000)],
                          0x00540000: [(0x00541000, 0x00580000, 0x3f000)],
                          0x00580000: [(0x00589000, 0x00590000, 0x7000),
                                       (0x01f12000, 0x02000000, 0xee000)],
                          0x005c0000: [(0x006b1000, 0x006c0000, 0xf000)],
                          0x01ef0000: [(0x01ef1000, 0x01f00000, 0xf000)],
                          0x02010000: [(0x02031000, 0x02050000, 0x1f000)],
                          0x02080000: [(0x035c2000, 0x036a0000, 0xde000),
                                       (0x02090000, 0x035c2000, 0x0)], # ???
                          0x021f0000: [(0x021f6000, 0x02230000, 0x3a000)],
                          0x03360000: [(0x03361000, 0x033a0000, 0x3f000)],
                          0x04030000: [(0x04031000, 0x04070000, 0x3f000)],
                          0x04110000: [(0x04111000, 0x04150000, 0x3f000)],
                          0x041c0000: [(0x041c1000, 0x04200000, 0x3f000)],
                          # 0x7efe0000 ...
                          }

putty_7124_win7 = TestDump('test/dumps/putty/putty.7124.dump')
putty_7124_win7.known_heaps = [(0x260000, 0x21000),
                               (0x2a0000, 0x9000),
                               (0x310000, 0x3000),
                               (0x320000, 0x6000),
                               (0x620000, 0x59000),
                               (0x1d40000, 0x1000),
                               (0x1d90000, 0x10000),
                               (0x1e60000, 0x1000),
                               (0x2c00000, 0x1000),
                               (0x3dc0000, 0x1000),
                               (0x3e00000, 0x1000),
                               (0x3f50000, 0x1000)]


ssh_1_i386_linux = TestDump('test/dumps/ssh/ssh.1')
ssh_1_i386_linux.known_heaps = [(0xb84e0000, 0x21000)]
ssh_1_i386_linux.known_records = {'struct_evp_cipher_ctx_st': [0xb84ee328, 0xb84ee3bc],
                                 }
