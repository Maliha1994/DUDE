import os
import difflib
from difflib import SequenceMatcher
from shutil import copyfile
import shutil


def deobfs(infile):
    # infile="filesystem.bin"
    # infile="unknownfs.bin"
    outfile = "media/deob_out.bin"

    file_stats = os.stat(infile)

    # magic=["73717368", "e0011985", "68737173", "73747395"]
    magic = ["7f1300000000", "137f00000000", "8f1300000000", "138f00000000", "0x2468", "0300000001000000FFFF0000", "0x53000000", "PFS/", "MPFS", "UBI!", "0x28cd3d45", "UBI23", "0x06101831", "0x1985", "sqsh", "hsqs", "sqlz", "qshs", "tqsh", "hsqt", "shsq", "0xEF53", "-rom1fs-\0", "ROMFS20v", "owowowowowowowowowowowowowowow", "OWOWOWOWOWOWOWOWOWOWOWOWOWOWOW", "00CD00101", "01CD0010100", "0x1b031336", "WDK202.000", "DOSEMU\0", "COWD03", "COWD02", "VMDK", "KDMV", "QFIFB", "FS3C3C", "0xbd9a", "EB109000", "EB7EFF00"]
    fp_in = open(infile, "rb")
    magic_ut = fp_in.read(4)
    fp_in.close()
    # print(magic_ut)
    hex_4 = magic_ut.hex()
    # print(hex_4)

    dist = []
    for mag in magic:
        ratio = SequenceMatcher(None, str(hex_4), str(mag))
        r = ratio.ratio()
        dist.append(r)

    order = []
    for itr in range(0, len(dist)):
        max_num = max(dist)
        max_index = dist.index(max_num)
        order.append(max_index)
        dist[max_index] = 0

    # print(order)
    success_flag = 0
    j = 1
    i = 0
    while (j):
        fp_in = open(infile, "rb")
        fp_out = open(outfile, "wb")
        # print(magic[order[i]])
        magic_org = bytes.fromhex(str(magic[order[i]]))
        # print(magic_ut)
        fp_out.write(magic_org)
        size = file_stats.st_size - 4
        fp_in.seek(4)
        for x in range(0, size, 1):
            rest_ut = fp_in.read(1)
            fp_out.write(rest_ut)
        fp_in.close()
        fp_out.close()

        shutil.copyfile("media/deob_out.bin", "static/firmware-mod-kit-master/deob_out.bin")
        ext_cmd2 = "cd static/firmware-mod-kit-master && ./unsquashfs_all.sh deob_out.bin"
        os.system(ext_cmd2)
        source = "static/firmware-mod-kit-master/squashfs-root/"
        dest = "media/ext_firm/"
        fl = os.path.exists(source)
        if fl != 0:
            files = os.listdir(source)
            for f in files:
                shutil.move(source + f, dest)
            rm_cmd = "rm -r " + source
            os.system(rm_cmd)
            # print("Successfully unpacked")
            j = 0
            success_flag = 1
        elif i <= len(order):
            print("deobfs Iteration: " + str(i + 1))
            i += 1
            if i == len(order):
                j = 0

    rm_cmd = "rm  media/deob_out.bin"
    rm_cmd2 = "rm  static/firmware-mod-kit-master/deob_out.bin"
    os.system(rm_cmd)
    os.system(rm_cmd2)
    return success_flag
