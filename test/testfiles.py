# /bin/python
# -*- coding: utf-8 -*-

class TestDump(object):
    def __init__(self, dumpname):
        self.dumpname = dumpname
        self.known_heaps = []
        self.known_segments = []
        self.known_ucr = []


# 2015-08-18
zeus_1668_vmtoolsd_exe = TestDump('/home/jal/outputs/vol/zeus.vmem.1668.dump')
zeus_1668_vmtoolsd_exe.known_heaps = [(0x00150000, 0x100000),
                                      (0x00250000, 0x10000),
                                      (0x003f0000, 0x10000),
                                      (0x00730000, 0xc8000), # testing 0x00670000-0x00738000
                                      (0x00860000, 0x300000),
                                      (0x00b70000, 0x10000),
                                      (0x00ba0000, 0x10000),
                                      (0x01620000, 0x80000),
                                      (0x01eb0000, 0x10000),
                                      (0x01ec0000, 0x100000),
                                      (0x5d09d000, 0x97000), #
                                      (0x769f7000, 0xb3000), #
                                      (0x7f6f0000, 0x100000)]



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

# 2015-08-18 unverified
zeus_856_svchost_exe = TestDump('/home/jal/outputs/vol/zeus.vmem.856.dump')
zeus_856_svchost_exe.known_heaps = [(0x00090000, 0x100000),
                                    (0x00190000, 0x10000),
                                    (0x001a0000, 0x10000),
                                    (0x00350000, 0x10000),
                                    (0x003b0000, 0x10000),
                                    (0x00c30000, 0x80000),
                                    (0x00d60000, 0x10000),
                                    (0x00e20000, 0x10000),
                                    (0x00e80000, 0x10000),
                                    (0x7f6f0000, 0x100000)]

# putty.1.dump is a win7 32 bits memory dump
putty_1_win7 = TestDump('test/dumps/putty/putty.1.dump')
putty_1_win7.known_heaps = [(0x00390000, 0x3000),
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
                            # from free stuf - erroneous
                            #( 0x0061a000, 1200),
                            ]
