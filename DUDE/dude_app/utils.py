import os
import shutil
import subprocess
import pytz
import time
from datetime import datetime

import PyPDF2
import numpy as np
from celery import shared_task
from celery.utils.log import get_task_logger
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from fpdf import FPDF
from PyPDF2 import PdfFileWriter, PdfFileReader, PdfFileMerger

import unicodedata
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from matplotlib.pyplot import figure
import matplotlib
import matplotlib.backends.backend_pdf
import matplotlib.patches as mpatches

from feast_app.badParse import badParse
from feast_app.bufAnalysis import bufAnalysis
from feast_app.code_similarity import sim_check
from feast_app.deobfuscation import deobfs
from feast_app.obsolete import obsolete_funcs

channel_layer = get_channel_layer()
logger = get_task_logger(__name__)


@shared_task(bind=True)
def unpack(self):
    time.sleep(1)
    send_logs('Starting Unpacker')
    if os.path.exists('static/firmware-mod-kit-master') == 0:
        send_logs('Setting Environment')
        os.system('unzip static/firmware-mod-kit-master.zip -d static/firmware-mod-kit-master')
        os.system('cd static/firmware-mod-kit-master/src && ./configure && make')
        send_logs('Environment Setup is completed')

    rm_ext_cmd = "rm -r -f media/ext_firm"
    rm_rp_cmd = "rm static/temp_results/Report.pdf"
    try:
        os.system(rm_ext_cmd)
        os.system(rm_rp_cmd)
    except:
        pass
    firm_ut0 = os.listdir('media/')
    firm_ut = 'media/'+firm_ut0[0]
    send_logs(firm_ut+' is under test')
    fp_fn = open('media/name.txt', 'w')
    fp_fn.writelines('Vendor and Device: ' + firm_ut0[0])
    fp_fn.close()

    entr_cmd = "binwalk -E -N " + str(firm_ut) + " > media/entropy.txt"
    send_logs('Detecting the encryption on the binary under test')
    os.system(entr_cmd)
    entr=0

    # calculate entropy to detect either binary is encrypted or not
    fp = open('media/entropy.txt', 'r')
    for i, line in enumerate(fp):
        if i == 3:
            try:
                entr1 = float(line[line.find("(") + 1:line.find(")")])
            except:
                entr1 = 0
        if i == 4:
            try:
                entr2 = float(line[line.find("(") + 1:line.find(")")])
            except:
                entr2 = 0
        if i == 5:
            try:
                entr3 = float(line[line.find("(") + 1:line.find(")")])
            except:
                entr3 = 0
            entr = entr1 + entr2 + entr3
    # print(entr)

    if entr == 2.824703:
        send_logs('Encrypted firmware found\nTrying to decrypt')
        dd_cmd = "dd if=" + str(firm_ut) + " bs=1 skip=40 of=media/filesystem.bin"
        os.system(dd_cmd)
        dec_cmd = "openssl aes-128-ecb -d -K 32383837436f6e6e373536340000 -in media/filesystem.bin -out media/decrypted.bin"
        os.system(dec_cmd)
        send_logs("Successfully decrypted\nTrying to unpack")
        rm_fs_cmd = 'rm media/filesystem.bin'
        rm_ent_cmd = 'rm media/entropy.txt'
        os.system(rm_fs_cmd)
        os.system(rm_ent_cmd)
        bin_cmd = "binwalk -e media/decrypted.bin --directory media/"
        os.system(bin_cmd)
        rm_dec_cmd = 'rm media/decrypted.bin'
        os.system(rm_dec_cmd)
        source2 = "media/_decrypted.bin.extracted/"
        flb = os.path.exists(source2)
        if flb != 0:
            mk_cmd = "mkdir media/ext_firm"
            os.system(mk_cmd)
            files2 = os.listdir(source2)
            for f2 in files2:
                shutil.move(source2 + f2, 'media/ext_firm')
            rm_cmd2 = "rm -r " + source2
            os.system(rm_cmd2)

            # copyfile("/home/ncsael/QCMAP_Web_CLIENT",
            #          "/home/ncsael/FEAST/ext_firm/squashfs-root-0/bin/QCMAP_Web_CLIENT")

        if os.path.exists('media/ext_firm'):
            perm = "chmod -R 777 media/ext_firm/"
            os.system(perm)
            send_logs("Successfully decrypted and unpacked")
        else:
            send_logs('Filesystem unpacking failed!')

    else:
        send_logs("No encryption on firmware\nSegregating the filesystem block")
        bwk_cmd1 = "binwalk " + str(firm_ut) + " > media/binwalk_out.txt"
        os.system(bwk_cmd1)
        try:
            fs_index = int(os.system("awk '/filesystem/{print $1}' media/binwalk_out.txt"))
        except:
            fs_index = 0
        dd_cmd = "dd if=" + str(firm_ut) + " bs=1 skip=" + str(fs_index) + " of=media/filesystem.bin"
        os.system(dd_cmd)
        send_logs("Filesystem block has been segregated")

        send_logs("Checking either its big endian compressed romfs")
        end_cmd = "./static/endian_convert media/filesystem.bin media/little_endian.cramfs"
        os.system(end_cmd)
        if os.path.isfile('media/little_endian.cramfs') != 0:
            
            cramfs_cmd = "static/firmware-mod-kit-master/src/uncramfs/uncramfs media/ext_firm media/little_endian.cramfs"
            os.system(cramfs_cmd)
            send_logs("Big endian compressed romfs found\n Trying to convert to little endian compressed romfs \n Conversion to little endian compressed romfs is successful\n Trying to unpack little endian compressed romfs\n Successfully unpacked")
            rm_lit = "rm media/little_endian.cramfs"
            rm_big = "rm media/big_endian.cramfs"
            os.system(rm_lit)
            os.system(rm_big)
        else:
            send_logs("Not a big or little endian compressed romfs")
            send_logs("Trying custom extractor")
            ext_cmd1 = "./static/custom_extractor "+str(firm_ut)+"  media/ext_firm"
            os.system(ext_cmd1)
            if len(os.listdir('media/ext_firm')) != 0:
                send_logs('Successfully Unpacked')
            else:
                send_logs("Trying FMK for Squashfs")
                shutil.copyfile("media/filesystem.bin", "static/firmware-mod-kit-master/filesystem.bin")
                ext_cmd2 = "cd static/firmware-mod-kit-master && ./unsquashfs_all.sh filesystem.bin"
                os.system(ext_cmd2)
                os.system('rm static/firmware-mod-kit-master/filesystem.bin')
                source = "static/firmware-mod-kit-master/squashfs-root/"
                fl = os.path.exists(source)
                if fl != 0:
                    files = os.listdir(source)
                    for f in files:
                        shutil.move(source + f, 'media/ext_firm')
                    rm_cmd = "rm -r " + source
                    os.system(rm_cmd)
                    send_logs("Successfully unpacked")
                else:
                    send_logs("Trying FMK for jffs2")
                    jffs2_dir = "rootfs"
                    try:
                        rm_jff = "rm -r -f " + jffs2_dir
                        os.system(rm_jff)
                    except:
                        pass
                    ext_cmd3 = "echo a | sudo -S ./static/firmware-mod-kit-master/src/jffs2/unjffs2 media/filesystem.bin"
                    # here a is the password of linux
                    os.system(ext_cmd3)
                    prm_cmd = "echo a | sudo -S chmod -R 777 " + jffs2_dir
                    os.system(prm_cmd)
                    if len(os.listdir(jffs2_dir)) != 0:
                        files = os.listdir(jffs2_dir)
                        for f in files:
                            shutil.move(jffs2_dir + "/" + f, 'media/ext_firm')
                        rm_cmd = "rm -r " + jffs2_dir
                        os.system(rm_cmd)
                        send_logs("Successfully unpacked JFFS2 filesystem")
                    else:
                        send_logs("Trying binwalk")
                        bin_cmd2 = "binwalk -e media/filesystem.bin --directory media/"
                        os.system(bin_cmd2)
                        source3 = "media/_filesystem.bin.extracted/"
                        print(source3)
                        flb2 = os.path.exists(source3)
                        if flb2 != 0:
                            files3 = os.listdir(source3)
                            for f3 in files3:
                                shutil.move(source3 + f3, 'media/ext_firm/')
                            rm_cmd3 = "rm -r " + source3
                            os.system(rm_cmd3)

        if os.path.exists('media/ext_firm/'):
            num_files2 = 0
            for root, dirs, files in os.walk('media/ext_firm'):
                num_files2 += len(files)
            if num_files2 > 30:
                cmd_perm = "echo a | sudo -S chmod 777 -R media/ext_firm"
                os.system(cmd_perm)
                send_logs("Successfully unpacked")
            else:
                send_logs("Trying deobfscator")
                success_flag = deobfs("media/filesystem.bin")
                if success_flag == 1:
                    cmd_perm = "echo a | sudo -S chmod 777 -R media/ext_firm"
                    os.system(cmd_perm)
                    send_logs("Deobfscator worked\nSuccessfully unpacked\n")
                else:
                    send_logs("Deobfscator did not worked\nFilesystem unpacking failed!\n")

    try:
        rm_cmd4 = "rm -r media/binwalk_out.txt"
        os.system(rm_cmd4)
        rm_cmd5 = "rm -r media/entropy.txt"
        os.system(rm_cmd5)
        rm_cmd6 = "rm -r media/filesystem.bin"
        os.system(rm_cmd6)
        cmd_perm = "echo a | sudo -S chmod 777 -R media/filesystem.bin.le"
        os.system(cmd_perm)
        rm_cmd7 = "rm -r media/filesystem.bin.le"
        os.system(rm_cmd7)
        firm_rm = 'rm ' + firm_ut
        os.system(firm_rm)
    except:
        pass


@shared_task(bind=True)
def static(self):
    time.sleep(1)
    send_logs('Starting Static Analysis')
    num_files = 0
    for root, dirs, files in os.walk('media/ext_firm'):
        num_files += len(files)
    if num_files < 30:
        send_logs('Analysis failed! Make sure filesystem is extracted correctly')
    else:
        pdf = FPDF(orientation='P', unit='mm', format='A4')
        pdf.add_page()

        rh = 0
        gh = 102
        bh = 204

        rh2 = 51
        gh2 = 153
        bh2 = 255

        rt = 0
        gt = 0
        bt = 0

        font_h = "Times"
        font_h2 = "Times"
        font_t = "Times"
        fsize_h = 14
        fsize_h2 = 12
        fsize_t = 12

        indx_h = 0
        indx_h2 = 0
        ln = 0

        # Search for password files
        send_logs("Searching for password files")
        indx_pasf = 0
        flag = 0
        arr1 = ['passwd', 'shadow', '.psk']
        for root, dirs, files in os.walk("media/ext_firm/"):
            for file in files:
                for db in arr1:
                    if file.endswith(db):
                        if flag == 0:
                            flag = 1
                            pdf.set_font(font_h, 'B', size=fsize_h)
                            pdf.set_text_color(rh, gh, bh)
                            indx_h += 1

                            pdf.cell(0, 10, txt="Details of Static Analysis Findings\n".format(ln), ln=1, align="C")
                            
                            pdf.cell(0, 10, txt=str(indx_h) + ". Admin Passwords\n".format(ln), ln=1, align="C")
                            ln += 1
                            pdf.set_font(font_t, size=fsize_t)
                            pdf.set_text_color(rt, gt, bt)
                            pdf.multi_cell(0, 5,
                                           txt="The credentials of admin accounts are stored in /etc/shadow or /etc/passwd files in the device OS. Acquiring these admin credentials can enable an attacker to login remotely from anywhere. The following admin passwords have been extracted from the router's firmware under examination:",
                                           align="J")
                            pdf.cell(0, 5, txt="".format(ln), ln=1, align="L")

                            pdf.set_text_color(rh2, gh2, bh2)
                            pdf.set_font(font_h2, size=fsize_h2)
                            pdf.cell(0, 5, txt="How to patch?\n".format(ln), ln=1, align="L")
                            ln += 1
                            pdf.set_text_color(rt, gt, bt)
                            pdf.set_font(font_t, size=fsize_t)
                            pdf.multi_cell(0, 5,
                                     txt="They should not pre-exist if they exist then they must be present in hashed form. Else, they should be generated during configuration.",
                                         align="J")
                            ln += 1
                            pdf.set_text_color(rh2, gh2, bh2)
                            pdf.set_font(font_h2, size=fsize_h2)
                            pdf.cell(0, 5, txt="Findings\n".format(ln), ln=1, align="L")
                            ln += 1

                        pdf.set_font(font_t, size=fsize_t)
                        pdf.set_text_color(rt, gt, bt)

                        indx_pasf += 1
                        pdf.cell(0, 5, txt=str(indx_pasf) + ". " + root + '/' + str(file) + "\n".format(ln), ln=1,
                                 align="L")
                        ln += 1

        send_logs("Found " + str(indx_pasf) + " password files")



        # Search for SSL related files
        send_logs("Searching for SSL related files")
        indx_sslf = 0
        flag = 0
        arr2 = ['.crt', '.pem', '.cer', 'p7b', 'p12', 'key']
        for root, dirs, files in os.walk("media/ext_firm/"):
            for file in files:
                for db in arr2:
                    if file.endswith(db):
                        if flag == 0:
                            flag = 1
                            pdf.set_font(font_h, 'B', size=fsize_h)
                            pdf.set_text_color(rh, gh, bh)
                            indx_h += 1
                            pdf.cell(0, 10, txt=str(indx_h) + ". SSL Certificates and Private Keys\n".format(ln), ln=1,
                                     align="C")
                            ln += 1
                            pdf.set_font(font_t, size=fsize_t)
                            pdf.set_text_color(rt, gt, bt)
                            pdf.multi_cell(0, 5,
                                           txt="Most of the vendors have included pre-generated self-signed SSL certificates in the hard coded form in the router's firmware, instead of generating them at the runtime. Some firmware binaries also includes private key in unencrypted PEM format, which can lead to serious security threats. By gaining access of these signed SSL certificates and private keys, HTTPS traffic can be decrypted. Moreover, man in the middle attack is also possible. Listed below are the extracted SSL certificates and keys:",
                                           align="J")
                            pdf.cell(0, 5, txt="".format(ln), ln=1, align="L")

                            pdf.set_text_color(rh2, gh2, bh2)
                            pdf.set_font(font_h2, size=fsize_h2)
                            pdf.cell(0, 5, txt="How to patch?\n".format(ln), ln=1, align="L")
                            ln += 1
                            pdf.set_text_color(rt, gt, bt)
                            pdf.set_font(font_t, size=fsize_t)
                            pdf.multi_cell(0, 5,
                                           txt="Privileges must be handled carefully on such file. Moreover, access should only have with the root users..",
                                           align="J")
                            pdf.cell(0, 5, txt="".format(ln), ln=1, align="L")

                            ln += 1

                            pdf.set_text_color(rh2, gh2, bh2)
                            pdf.set_font(font_h2, size=fsize_h2)
                            pdf.cell(0, 5, txt="Findings\n".format(ln), ln=1, align="L")
                            ln += 1

                        pdf.set_font(font_t, size=fsize_t)
                        pdf.set_text_color(rt, gt, bt)
                        indx_sslf += 1
                        pdf.cell(0, 5, txt=str(indx_sslf) + ". " + root + '/' + str(file) + "\n".format(ln), ln=1,
                                 align="L")
                        ln += 1

        send_logs("Found " + str(indx_sslf) + " SSL related files")



        # Search for SSH related files
        send_logs("Searching for SSH related files")
        indx_sshf = 0
        flag = 0
        arr3 = ['authorized_keys', 'authorized_keys', 'host_key', 'id_rsa', 'id_dsa', '.pub']
        for root, dirs, files in os.walk("media/ext_firm/"):
            for file in files:
                for db in arr3:
                    if file.endswith(db):
                        if flag == 0:
                            flag = 1
                            pdf.set_font(font_h, 'B', size=fsize_h)
                            pdf.set_text_color(rh, gh, bh)
                            indx_h += 1
                            pdf.cell(0, 10, txt=str(indx_h) + ". SSH Related Files\n".format(ln), ln=1, align="C")
                            ln += 1

                            pdf.set_font(font_t, size=fsize_t)
                            pdf.set_text_color(rt, gt, bt)
                            pdf.multi_cell(0, 5,
                                           txt="Access of SSH related files cause the leakage of sensitive information content. Some of them may provide the illegitimate access over the device. Extracted SSH related files extracted form the firmware binary are recorded below:",
                                           align="J")
                            pdf.cell(0, 5, txt="".format(ln), ln=1, align="L")

                            pdf.set_text_color(rh2, gh2, bh2)
                            pdf.set_font(font_h2, size=fsize_h2)
                            pdf.cell(0, 5, txt="How to patch?\n".format(ln), ln=1, align="L")
                            ln += 1
                            pdf.set_text_color(rt, gt, bt)
                            pdf.set_font(font_t, size=fsize_t)
                            pdf.multi_cell(0, 5,
                                           txt="Privileges must be handled carefully on such file. Moreover, access should only have with the root users.",
                                           align="J")
                            pdf.cell(0, 5, txt="".format(ln), ln=1, align="L")

                            ln += 1

                            pdf.set_text_color(rh2, gh2, bh2)
                            pdf.set_font(font_h2, size=fsize_h2)
                            pdf.cell(0, 5, txt="Findings\n".format(ln), ln=1, align="L")
                            ln += 1

                        pdf.set_font(font_t, size=fsize_t)
                        pdf.set_text_color(rt, gt, bt)
                        indx_sshf += 1
                        pdf.cell(0, 5, txt=str(indx_sshf) + ". " + root + '/' + str(file) + "\n".format(ln), ln=1,
                                 align="L")
                        ln += 1

        send_logs("Found " + str(indx_sshf) + " SSH related files")



        # Search for configuration files
        send_logs("Searching for configuration files")
        indx_cfgf = 0
        flag = 0
        arr4 = ['.conf', '.cfg', '.ini']
        for root, dirs, files in os.walk("media/ext_firm/"):
            for file in files:
                for db in arr4:
                    if file.endswith(db):
                        if flag == 0:
                            flag = 1
                            pdf.set_font(font_h, 'B', size=fsize_h)
                            pdf.set_text_color(rh, gh, bh)
                            indx_h += 1
                            pdf.cell(0, 10, txt=str(indx_h) + ". Configuration Files\n".format(ln), ln=1, align="C")
                            ln += 1

                            pdf.set_font(font_t, size=fsize_t)
                            pdf.set_text_color(rt, gt, bt)
                            pdf.multi_cell(0, 5,
                                           txt="Configuration files are critical as they contain authentication secret files, root directory of documents, and user admin details. We observed that in the majority of the cases, web servers run under as the root privileged user, which is a sign of risky configuration and design. Due to these issues, the security of the router's device can be compromised if any of the web components are found vulnerable. Extracted web configuration files and other configuration files are enumerated below:",
                                           align="J")
                            pdf.cell(0, 5, txt="".format(ln), ln=1, align="L")

                            pdf.set_text_color(rh2, gh2, bh2)
                            pdf.set_font(font_h2, size=fsize_h2)
                            pdf.cell(0, 5, txt="How to patch?\n".format(ln), ln=1, align="L")
                            ln += 1
                            pdf.set_text_color(rt, gt, bt)
                            pdf.set_font(font_t, size=fsize_t)
                            pdf.multi_cell(0, 5,
                                           txt="Configuration files must not be present in plain text.",
                                           align="J")
                            pdf.cell(0, 5, txt="".format(ln), ln=1, align="L")

                            ln += 1

                            pdf.set_text_color(rh2, gh2, bh2)
                            pdf.set_font(font_h2, size=fsize_h2)
                            pdf.cell(0, 5, txt="Findings\n".format(ln), ln=1, align="L")
                            ln += 1

                        pdf.set_font(font_t, size=fsize_t)
                        pdf.set_text_color(rt, gt, bt)
                        indx_cfgf += 1
                        pdf.cell(0, 5, txt=str(indx_cfgf) + ". " + root + '/' + str(file) + "\n".format(ln), ln=1,
                                 align="L")
                        ln += 1

        send_logs("Found " + str(indx_cfgf) + " configuration files")



        # Search for database files
        send_logs("Searching for database files")
        indx_dbf = 0
        flag = 0
        arr5 = ['.db', '.sqlite', '.sqlite3']
        for root, dirs, files in os.walk("media/ext_firm/"):
            for file in files:
                for db in arr5:
                    if file.endswith(db):
                        if flag == 0:
                            flag = 1
                            pdf.set_font(font_h, 'B', size=fsize_h)
                            pdf.set_text_color(rh, gh, bh)
                            indx_h += 1
                            pdf.cell(0, 10, txt=str(indx_h) + ". Database Files\n".format(ln), ln=1, align="C")
                            ln += 1

                            pdf.set_font(font_t, size=fsize_t)
                            pdf.set_text_color(rt, gt, bt)
                            pdf.multi_cell(0, 5,
                                           txt="Vulnerabilites present in many devices are related to the identification of malicious codes inserted by the attackers. These include the Standard Query Languages (SQL) injection scripts. Given below are the extracted database files:",
                                           align="J")
                            pdf.cell(0, 5, txt="".format(ln), ln=1, align="L")

                            pdf.set_text_color(rh2, gh2, bh2)
                            pdf.set_font(font_h2, size=fsize_h2)
                            pdf.cell(0, 5, txt="How to patch?\n".format(ln), ln=1, align="L")
                            ln += 1
                            pdf.set_text_color(rt, gt, bt)
                            pdf.set_font(font_t, size=fsize_t)
                            pdf.multi_cell(0, 5,
                                           txt=" They should be TDE encrypted.",
                                           align="J")
                            pdf.cell(0, 5, txt="".format(ln), ln=1, align="L")

                            ln += 1

                            pdf.set_text_color(rh2, gh2, bh2)
                            pdf.set_font(font_h2, size=fsize_h2)
                            pdf.cell(0, 5, txt="Findings\n".format(ln), ln=1, align="L")
                            ln += 1

                        pdf.set_font(font_t, size=fsize_t)
                        pdf.set_text_color(rt, gt, bt)
                        indx_dbf += 1
                        pdf.cell(0, 5, txt=str(indx_dbf) + ". " + root + '/' + str(file) + "\n".format(ln), ln=1,
                                 align="L")
                        ln += 1

        send_logs("Found " + str(indx_dbf) + " database files")



        # Search for malicious patterns in files
        malptr_total = 0
        send_logs("Searching for malicious patterns in files")
        pdf.set_font(font_h, 'B', size=fsize_h)
        pdf.set_text_color(rh, gh, bh)
        indx_h += 1
        pdf.cell(0, 10, txt=str(indx_h) + ". Malicious Patterns\n".format(ln), ln=1, align="C")
        ln += 1

        pdf.set_font(font_t, size=fsize_t)
        pdf.set_text_color(rt, gt, bt)
        pdf.multi_cell(0, 5,
                       txt="If malicious patterns exist then the session between the client and server are not encrypted without a workaround. Therefore, those with access to the TCP/IP packet flow between hosts can observe all the traffic, listen in, and record potentially sensitive information like logins and passwords of users connecting to the servers. In depth search against the malicious patterns highlighted in the tested router's firmware files based upon the vulnerabilites database are given below:",
                       align="J")
        pdf.cell(0, 5, txt="".format(ln), ln=1, align="L")

        pdf.set_text_color(rh2, gh2, bh2)
        pdf.set_font(font_h2, size=fsize_h2)
        pdf.cell(0, 5, txt="How to patch?\n".format(ln), ln=1, align="L")
        ln += 1
        pdf.set_text_color(rt, gt, bt)
        pdf.set_font(font_t, size=fsize_t)
        pdf.multi_cell(0, 5,
                       txt="Kerberos protocol should be used and Kerberos can essentially be layered over telnet communication inorder to verify the identity while avoiding login information exploitation.",
                       align="J")
        pdf.cell(0, 5, txt="".format(ln), ln=1, align="L")

        ln += 1

        pdf.set_text_color(rh2, gh2, bh2)
        pdf.set_font(font_h2, size=fsize_h2)
        pdf.cell(0, 5, txt="Findings\n".format(ln), ln=1, align="L")
        ln += 1



        indx_ptrf = 0
        arr6 = ['upgrade', 'admin', 'root', 'password', 'passwd', 'pwd', 'dropbear', 'ssl', 'private key', 'telnet',
                'telnetd', 'secret', 'pgp', 'gpg', 'token', 'api key', 'oauth']
        lp_ptrn = 0
        indx_arr = -1;
        ptr_val = []
        while lp_ptrn < len(arr6):
            indx_arr += 1
            ptrn_cmd = "grep -lsirnw  media/ext_firm/ -e ""'" + arr6[
                lp_ptrn] + "'"" | tee -a media/Credentials.txt"
            rc1, ptrn = subprocess.getstatusoutput(ptrn_cmd)
            if ptrn:
                if lp_ptrn == 0:
                    pdf.set_font(font_h2, 'B', size=fsize_h2)
                    pdf.set_text_color(rh2, gh2, bh2)
                    indx_h2 += 1
                    pdf.cell(0, 10, txt="\n" + str(indx_h2) + ". " + arr6[lp_ptrn] + "\n".format(ln), ln=1, align="L")
                    ln += 1
                    pdf.set_font(font_t, size=fsize_t)
                    pdf.set_text_color(rt, gt, bt)
                    indx_ptrf += 1
                    ptrn2 = ptrn.splitlines()
                    lp1_c = 0
                    for lp1 in ptrn2:
                        pdf.cell(0, 5, txt=str(lp1_c + 1) + ". " + ptrn2[lp1_c] + "\n".format(ln), ln=1, align="L")
                        ln += 1
                        lp1_c += 1
                    ptr_val.append(arr6[indx_arr] + ":" + str(lp1_c))
                    malptr_total = malptr_total + lp1_c
                else:
                    pdf.set_font(font_h2, 'B', size=fsize_h2)
                    pdf.set_text_color(rh2, gh2, bh2)
                    indx_h2 += 1
                    pdf.cell(0, 10, txt="\n" + str(indx_h2) + ". " + arr6[lp_ptrn] + "\n".format(ln), ln=1, align="L")
                    ln += 1
                    pdf.set_font(font_t, size=fsize_t)
                    pdf.set_text_color(rt, gt, bt)
                    indx_ptrf += 1
                    ptrn2 = ptrn.splitlines()
                    lp1_c = 0
                    for lp1 in ptrn2:
                        stripped = ''
                        for ca in ptrn2[lp1_c]:
                            stripped += ca if len(ca.encode(encoding='utf_8')) == 1 else ''
                        pdf.cell(0, 5, txt=str(lp1_c + 1) + ". " + stripped + "\n".format(ln), ln=1, align="L")
                        lp1_c += 1
                        ln += 1
                    ptr_val.append(arr6[indx_arr] + ":" + str(lp1_c))
                    malptr_total = malptr_total + lp1_c
            lp_ptrn += 1

        x_axis = []
        y_axis = []
        lpi = 0
        for ptrn3 in ptr_val:
            ptrn_valc = ptr_val[lpi].split(':')
            x_axis.append(ptrn_valc[0])
            y_axis.append(ptrn_valc[1])
            lpi += 1

        y_pos = np.arange(len(x_axis))
        int_y = []
        val_c = 0
        for val in y_axis:
            int_y.append(int(y_axis[val_c]))
            val_c += 1

        plt.figure(1)
        plt.bar(y_pos, int_y, align='center', alpha=1)
        plt.xticks(y_pos, x_axis)
        plt.xlabel('Detected Malicious Patterns', fontsize=22)
        plt.ylabel('Malicious Patterns Count', fontsize=22)
        plt.suptitle('Detected Malicious Patterns of Firmware Binary Under Test', fontsize=30, color='C0')

        fig = matplotlib.pyplot.gcf()
        fig.set_size_inches(22, 10)
        fig.savefig('media/patterns.png', dpi=100)
        plt.close()

        send_logs("Found " + str(malptr_total) + " malicious patterns in files")



        # Search for shell scripts
        send_logs("Searching for shell scripts")
        indx_sscr = 0
        flag = 0
        arr7 = ['.sh']
        for root, dirs, files in os.walk("media/ext_firm/"):
            for file in files:
                for db in arr7:
                    if file.endswith(db):
                        if flag == 0:
                            flag = 1
                            pdf.set_font(font_h, 'B', size=fsize_h)
                            pdf.set_text_color(rh, gh, bh)
                            indx_h += 1
                            pdf.cell(0, 10, txt="\n" + str(indx_h) + ". Shell Scripts\n".format(ln), ln=1, align="C")
                            ln += 1

                            pdf.set_font(font_t, size=fsize_t)
                            pdf.set_text_color(rt, gt, bt)
                            pdf.multi_cell(0, 5,
                                           txt="If they exist then using them malicious activities are possible. The list of shell scripts are given below.",
                                           align="J")
                            pdf.cell(0, 5, txt="".format(ln), ln=1, align="L")


                            pdf.set_text_color(rh2, gh2, bh2)
                            pdf.set_font(font_h2, size=fsize_h2)
                            pdf.cell(0, 5, txt="How to patch?\n".format(ln), ln=1, align="L")
                            ln += 1
                            pdf.set_text_color(rt, gt, bt)
                            pdf.set_font(font_t, size=fsize_t)
                            pdf.multi_cell(0, 5,
                                           txt="Privileges must be handled carefully on such file. Moreover, access should only have with the root users.",
                                           align="J")
                            pdf.cell(0, 5, txt="".format(ln), ln=1, align="L")

                            ln += 1

                            pdf.set_text_color(rh2, gh2, bh2)
                            pdf.set_font(font_h2, size=fsize_h2)
                            pdf.cell(0, 5, txt="Findings\n".format(ln), ln=1, align="L")
                            ln += 1

                        pdf.set_font(font_t, size=fsize_t)
                        pdf.set_text_color(rt, gt, bt)
                        indx_sscr += 1
                        pdf.cell(0, 5, txt=str(indx_sscr) + ". " + root + '/' + str(file) + "\n".format(ln), ln=1,
                                 align="L")
                        ln += 1

        send_logs("Found " + str(indx_sscr) + " shell scripts")

        # Search for miscellaneous binary files
        send_logs("Searching for miscellaneous binary files")
        indx_mbin = 0
        flag = 0
        arr8 = ['.bin']
        for root, dirs, files in os.walk("media/ext_firm/"):
            for file in files:
                for db in arr8:
                    if file.endswith(db):
                        if flag == 0:
                            flag = 1
                            pdf.set_font(font_h, 'B', size=fsize_h)
                            pdf.set_text_color(rh, gh, bh)
                            indx_h += 1
                            pdf.cell(0, 10, txt="\n" + str(indx_h) + ". Miscellaneous Binary Files\n".format(ln), ln=1,
                                     align="C")
                            ln += 1

                            pdf.set_font(font_t, size=fsize_t)
                            pdf.set_text_color(rt, gt, bt)
                            pdf.multi_cell(0, 5, txt="The extracted miscellaneous binary files are listed below:",
                                           align="J")
                            pdf.cell(0, 5, txt="".format(ln), ln=1, align="L")

                            pdf.set_text_color(rh2, gh2, bh2)
                            pdf.set_font(font_h2, size=fsize_h2)
                            pdf.cell(0, 5, txt="How to patch?\n".format(ln), ln=1, align="L")
                            ln += 1
                            pdf.set_text_color(rt, gt, bt)
                            pdf.set_font(font_t, size=fsize_t)
                            pdf.multi_cell(0, 5,
                                           txt=" They should be present in encrypted form.",
                                           align="J")
                            pdf.cell(0, 5, txt="".format(ln), ln=1, align="L")

                            ln += 1

                            pdf.set_text_color(rh2, gh2, bh2)
                            pdf.set_font(font_h2, size=fsize_h2)
                            pdf.cell(0, 5, txt="Findings\n".format(ln), ln=1, align="L")
                            ln += 1

                        pdf.set_font(font_t, size=fsize_t)
                        pdf.set_text_color(rt, gt, bt)
                        indx_mbin += 1
                        pdf.cell(0, 5, txt=str(indx_mbin) + ". " + root + '/' + str(file) + "\n".format(ln), ln=1,
                                 align="L")
                        ln += 1

        send_logs("Found " + str(indx_mbin) + " miscellaneous binary files")

        # Search for third party software and libraries files
        send_logs("Searching for third party softwares and libraries files")
        indx_ibin = 0
        flag = 0
        arr9 = ['ssh', 'sshd', 'scp', 'sftp', 'tftp', 'dropbear', 'busybox', 'telnet', 'telnetd', 'openssl', 'tddp']
        for root, dirs, files in os.walk("media/ext_firm/"):
            for file in files:
                for db in arr9:
                    if file.endswith(db):
                        if flag == 0:
                            flag = 1
                            pdf.set_font(font_h, 'B', size=fsize_h)
                            pdf.set_text_color(rh, gh, bh)
                            indx_h += 1
                            pdf.cell(0, 10,
                                     txt="\n" + str(indx_h) + ". Third Party Softwares and Libraries\n".format(ln),
                                     ln=1, align="C")
                            ln += 1

                            pdf.set_font(font_t, size=fsize_t)
                            pdf.set_text_color(rt, gt, bt)
                            pdf.multi_cell(0, 5,
                                           txt="FEAST has analyzed the bad release management practices followed by router firmware vendors, by the successful identification of different open source libraries and third party softwares. These libraries can be exploited thereby, causing a great security hazard. Different extracted executables like busybox, telnet, ssh, tftp, and so on are found, on which different reverse engineering techniques can be applied for injecting malicious scripts and launching the attacks.",
                                           align="J")
                            pdf.cell(0, 5, txt="".format(ln), ln=1, align="L")



                            pdf.set_text_color(rh2, gh2, bh2)
                            pdf.set_font(font_h2, size=fsize_h2)
                            pdf.cell(0, 5, txt="Findings\n".format(ln), ln=1, align="L")
                            ln += 1

                        pdf.set_font(font_t, size=fsize_t)
                        pdf.set_text_color(rt, gt, bt)
                        indx_ibin += 1
                        pdf.cell(0, 5, txt=str(indx_ibin) + ". " + root + '/' + str(file) + "\n".format(ln), ln=1,
                                 align="L")
                        ln += 1

        send_logs("Found " + str(indx_ibin) + " third party softwares and libraries files")

        # Search for web servers
        send_logs("Searching for web servers")
        indx_ws = 0
        flag = 0
        arr10 = ['apache', 'lighttpd', 'alphapd', 'httpd', 'mini_httpd', 'webs', 'dropbear', 'login']
        for root, dirs, files in os.walk("media/ext_firm/"):
            for file in files:
                for db in arr10:
                    if file.endswith(db):
                        if flag == 0:
                            flag = 1
                            pdf.set_font(font_h, 'B', size=fsize_h)
                            pdf.set_text_color(rh, gh, bh)
                            indx_h += 1
                            pdf.cell(0, 10, txt="\n" + str(indx_h) + ". Web Servers\n".format(ln), ln=1, align="C")
                            ln += 1

                            pdf.set_font(font_t, size=fsize_t)
                            pdf.set_text_color(rt, gt, bt)
                            pdf.multi_cell(0, 5, txt="The extracted web server executables are listed below:",
                                           align="J")
                            pdf.cell(0, 5, txt="".format(ln), ln=1, align="L")

                        pdf.set_font(font_t, size=fsize_t)
                        pdf.set_text_color(rt, gt, bt)
                        indx_ws += 1
                        pdf.cell(0, 5, txt=str(indx_ws) + ". " + root + '/' + str(file) + "\n".format(ln), ln=1,
                                 align="L")
                        ln += 1

        send_logs("Found " + str(indx_ws) + " web servers")

        # Search for hard coded IP addresses
        send_logs("Searching for hard coded IP addresses")
        flag = 0
        indx_ip = 0
        find_cmd1 = "grep -sRIEho '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' --exclude-dir='dev' media/ext_firm/ | sort | uniq"
        rc1, ipaddr = subprocess.getstatusoutput(find_cmd1)

        if ipaddr:
            if flag == 0:
                flag = 1
                pdf.set_font(font_h, 'B', size=fsize_h)
                pdf.set_text_color(rh, gh, bh)
                indx_h += 1
                pdf.cell(0, 10, txt="\n" + str(indx_h) + ". Hard Coded IP Addresses\n".format(ln), ln=1, align="C")
                ln += 1

                pdf.set_font(font_t, size=fsize_t)
                pdf.set_text_color(rt, gt, bt)
                pdf.multi_cell(0, 5,
                               txt="Majority of the embedded devices use  hard coded IP addresses which are used for remote code execution of malicious scripts. The monitored hard coded IP addresses are enumerated below:",
                               align="J")
                pdf.cell(0, 5, txt="".format(ln), ln=1, align="L")

            pdf.set_font(font_t, size=fsize_t)
            pdf.set_text_color(rt, gt, bt)
            ipaddr2 = ipaddr.splitlines()
            try:
                ipaddr2 = ipaddr.splitlines()
            except:
                ipaddr2 = 0;

        for lp1 in ipaddr2:
            pdf.cell(0, 5, txt=str(indx_ip + 1) + ". " + ipaddr2[indx_ip] + "\n".format(ln), ln=1, align="L")
            indx_ip += 1
            ln += 1

        send_logs("Found " + str(indx_ip) + " hard coded IP addresses")

        # Search for hard coded urls
        send_logs("Searching for hard coded urls")
        flag = 0
        indx_url = 0
        find_cmd2 = "grep -sRIEho '(http|https)://['^/']+' --exclude-dir='dev' media/ext_firm/ | sort | uniq"
        rc2, urls = subprocess.getstatusoutput(find_cmd2)
        # urls.encode(..., 'ignore')

        if urls:
            if flag == 0:
                flag = 1
                pdf.set_font(font_h, 'B', size=fsize_h)
                pdf.set_text_color(rh, gh, bh)
                indx_h += 1
                pdf.cell(0, 10, txt="\n" + str(indx_h) + ". Hard Coded URLs\n".format(ln), ln=1, align="C")
                ln += 1

                pdf.set_font(font_t, size=fsize_t)
                pdf.set_text_color(rt, gt, bt)
                pdf.multi_cell(0, 5,
                               txt="The following are the exfiltrated hard coded URLs from the firmware binary under test:",
                               align="J")
                pdf.cell(0, 5, txt="".format(ln), ln=1, align="L")

            pdf.set_font(font_t, size=fsize_t)
            pdf.set_text_color(rt, gt, bt)
            urls2 = urls.splitlines()
            for lp2 in urls2:
                stripped_text = ''
                for c in urls2[indx_url]:
                    stripped_text += c if len(c.encode(encoding='utf_8')) == 1 else ''

                pdf.cell(0, 5, txt=str(indx_url + 1) + ". " + stripped_text + "\n".format(ln), ln=1, align="L")
                indx_url += 1
                ln += 1

        send_logs("Found " + str(indx_url) + " hard coded urls")

        # Search for email addresses
        send_logs("Searching for email addresses")
        flag = 0
        indx_email = 0
        find_cmd3 = "grep -sRIEho '([[:alnum:]_.-]+@[[:alnum:]_.-]+?\.[[:alpha:].]{2,6})'  --exclude-dir='dev' media/ext_firm/ | sort | uniq"
        rc3, emails = subprocess.getstatusoutput(find_cmd3)

        if emails:
            if flag == 0:
                flag = 1
                pdf.set_font(font_h, 'B', size=fsize_h)
                pdf.set_text_color(rh, gh, bh)
                indx_h += 1
                pdf.cell(0, 10, txt="\n" + str(indx_h) + ". Email Addresses\n".format(ln), ln=1, align="C")
                ln += 1

                pdf.set_font(font_t, size=fsize_t)
                pdf.set_text_color(rt, gt, bt)
                pdf.multi_cell(0, 5,
                               txt="The following are the exfiltrated hard coded email addresses from the firmware binary under test:",
                               align="J")
                pdf.cell(0, 5, txt="".format(ln), ln=1, align="L")

            pdf.set_font(font_t, size=fsize_t)
            pdf.set_text_color(rt, gt, bt)
            emails2 = emails.splitlines()
            for lp3 in emails2:
                pdf.cell(0, 5, txt=str(indx_email + 1) + ". " + emails2[indx_email] + "\n".format(ln), ln=1, align="L")
                indx_email += 1
                ln += 1

        send_logs("Found " + str(indx_email) + " email addresses")

        # Search for backdoor containing files
        send_logs("Searching for backdoor containing files")
        flag = 0
        indx_bkdr = 0
        find_cmd5 = "find media/ext_firm/ -type f -print | xargs grep 'xmlset_roodkcableoj28840ybtide'"
        rc5, bkdr = subprocess.getstatusoutput(find_cmd5)

        if bkdr:
            if flag == 0:
                flag = 1
                pdf.set_font(font_h, 'B', size=fsize_h)
                pdf.set_text_color(rh, gh, bh)
                indx_h += 1
                pdf.cell(0, 10, txt="\n" + str(indx_h) + ". Backdoor Containing Files\n".format(ln), ln=1, align="C")
                ln += 1

                pdf.set_font(font_t, size=fsize_t)
                pdf.set_text_color(rt, gt, bt)
                pdf.multi_cell(0, 5,
                               txt="Detailed analysis on executables yeild the presence of backdoor string \"xmlset_roodkcableoj28840ybtide\" which enables adminstration authentication bypass. Following files contain the predescribed string:",
                               align="J")
                pdf.cell(0, 5, txt="".format(ln), ln=1, align="L")

            pdf.set_font(font_t, size=fsize_t)
            pdf.set_text_color(rt, gt, bt)
            bkdr2 = bkdr.splitlines()
            for lp4 in bkdr2:
                strippedbkdr = ''
                for caa in bkdr2[indx_bkdr]:
                    strippedbkdr += caa if len(caa.encode(encoding='utf_8')) == 1 else ''
                pdf.multi_cell(0, 5, txt=str(indx_bkdr + 1) + ". " + strippedbkdr + "\n".format(ln), align="L")
                indx_bkdr += 1
                ln += 1

        send_logs("Found " + str(indx_bkdr) + " backdoor containing files")

        # Search for hard coded passwords
        send_logs("Searching for hard coded passwords")
        flag = 0
        indx_hpas = 0
        find_cmd4 = "find media/ext_firm/ -type f -print | xargs grep 'password='"
        rc4, pas = subprocess.getstatusoutput(find_cmd4)

        if pas:
            if flag == 0:
                flag = 1
                pdf.set_font(font_h, 'B', size=fsize_h)
                pdf.set_text_color(rh, gh, bh)
                indx_h += 1
                pdf.cell(0, 10, txt="\n" + str(indx_h) + ". Hard Coded Password\n".format(ln), ln=1, align="C")
                ln += 1
                pdf.set_font(font_t, size=fsize_t)
                pdf.set_text_color(rt, gt, bt)
                pdf.multi_cell(0, 5,
                               txt="Scanning of the sensitive information residing in the examined firmware binary has yeided the following hard coded passwords:",
                               align="J")
                pdf.cell(0, 5, txt="".format(ln), ln=1, align="L")

                pdf.set_text_color(rh2, gh2, bh2)
                pdf.set_font(font_h2, size=fsize_h2)
                pdf.cell(0, 5, txt="How to patch?\n".format(ln), ln=1, align="L")
                ln += 1
                pdf.set_text_color(rt, gt, bt)
                pdf.set_font(font_t, size=fsize_t)
                pdf.multi_cell(0, 5,
                               txt=" They should be present in encrypted form.",
                               align="J")
                pdf.cell(0, 5, txt="".format(ln), ln=1, align="L")

                ln += 1

                pdf.set_text_color(rh2, gh2, bh2)
                pdf.set_font(font_h2, size=fsize_h2)
                pdf.cell(0, 5, txt="Findings\n".format(ln), ln=1, align="L")
                ln += 1

            pdf.set_font(font_t, size=fsize_t)
            pdf.set_text_color(rt, gt, bt)
            pas2 = pas.splitlines()
            # pdf.add_font('DejaVu', '', 'static/DejaVuSansCondensed.ttf', uni=True)
            # pdf.set_font('DejaVu', '', 12)
            for lp5 in pas2:
                pdf.multi_cell(0, 5, txt=str(indx_hpas + 1) + ". " + pas2[indx_hpas] + "\n".format(ln), align="L")
                indx_hpas += 1
                ln += 1

        send_logs("Found " + str(indx_hpas) + " hard coded passwords")

        w_pass = indx_pasf * 2
        w_ssl = indx_sslf * 5
        w_ssh = indx_sshf * 2
        w_cfg = indx_cfgf * 3
        w_db = indx_dbf * 2
        w_shel = indx_sscr * 3
        w_bfile = indx_mbin
        w_3rd = indx_ibin * 2
        w_webs = indx_ws
        w_ip = indx_ip * 4
        w_url = indx_url * 3
        w_bkdr = indx_bkdr
        w_hpass = indx_hpas
        w_email = indx_email
        w_malptr = malptr_total * 3

        c_pass = '#74DF00'
        c_ssl = '#74DF00'
        c_ssh = '#74DF00'
        c_cfg = '#74DF00'
        c_db = '#74DF00'
        c_shel = '#74DF00'
        c_bfile = '#74DF00'
        c_3rd = '#74DF00'
        c_webs = '#74DF00'
        c_ip = '#74DF00'
        c_url = '#74DF00'
        c_bkdr = '#74DF00'
        c_hpass = '#74DF00'
        c_email = '#74DF00'
        c_malptr = '#74DF00'

        if w_pass >= 0 and w_pass <= 5:
            lvl_pass = 10
            c_pass = '#74DF00'
        elif w_pass > 5 and w_pass <= 10:
            lvl_pass = 35
            c_pass = '#FFFF00'
        elif w_pass > 10 and w_pass <= 20:
            lvl_pass = 60
            c_pass = '#FF8000'
        elif w_pass >= 20:
            lvl_pass = 90
            c_pass = '#FA5858'

        lvl_ssl = 5
        if w_ssl >= 0:
            lvl_ssl = 90
            c_ssl = '#FA5858'

        lvl_ssh = 5
        if w_ssh >= 0 and w_ssh <= 5:
            lvl_ssh = 10
            c_ssh = '#74DF00'
        elif w_ssh > 5 and w_ssh <= 10:
            lvl_ssh = 35
            c_ssh = '#FFFF00'
        elif w_ssh > 10 and w_ssh <= 20:
            lvl_ssh = 60
            c_ssh = '#FF8000'
        elif w_ssh >= 20:
            lvl_ssh = 90
            c_ssh = '#FA5858'

        lvl_cfg = 5
        if w_cfg >= 0 and w_cfg <= 5:
            lvl_cfg = 10
            c_cfg = '#74DF00'
        elif w_cfg > 5 and w_cfg <= 30:
            lvl_cfg = 35
            c_cfg = '#FFFF00'
        elif w_cfg > 30 and w_cfg <= 60:
            lvl_cfg = 60
            c_cfg = '#FF8000'
        elif w_cfg >= 60:
            lvl_cfg = 90
            c_cfg = '#FA5858'

        lvl_db = 5
        if w_db >= 0 and w_db <= 5:
            lvl_db = 10
            c_db = '#74DF00'
        elif w_db > 5 and w_db <= 10:
            lvl_db = 35
            c_db = '#FFFF00'
        elif w_db > 10 and w_db <= 20:
            lvl_db = 60
            c_db = '#FF8000'
        elif w_db >= 20:
            lvl_db = 90
            c_db = '#FA5858'

        lvl_shel = 5
        if w_shel >= 0 and w_shel <= 5:
            lvl_shel = 10
            c_shel = '#74DF00'
        elif w_shel > 5 and w_shel <= 20:
            lvl_shel = 35
            c_shel = '#FFFF00'
        elif w_shel > 20 and w_shel <= 100:
            lvl_shel = 60
            c_shel = '#FF8000'
        elif w_shel >= 100:
            lvl_shel = 90
            c_shel = '#FA5858'

        lvl_bfile = 5
        if w_bfile >= 0 and w_bfile <= 10:
            lvl_bfile = 10
            c_bfile = '#74DF00'
        elif w_bfile > 10 and w_bfile <= 30:
            lvl_bfile = 35
            c_bfile = '#FFFF00'
        elif w_bfile > 30 and w_bfile <= 50:
            lvl_bfile = 60
            c_bfile = '#FF8000'
        elif w_bfile > 50:
            lvl_bfile = 90
            c_bfile = '#FA5858'

        lvl_b3rd = 5
        if w_3rd >= 0 and w_3rd <= 5:
            lvl_b3rd = 10
            c_3rd = '#74DF00'
        elif w_3rd > 5 and w_3rd <= 15:
            lvl_b3rd = 35
            c_3rd = '#FFFF00'
        elif w_3rd > 15 and w_3rd <= 25:
            lvl_b3rd = 60
            c_3rd = '#FF8000'
        elif w_3rd >= 25:
            lvl_b3rd = 90
            c_3rd = '#FA5858'

        lvl_b3rd = 5
        if w_3rd >= 0 and w_3rd <= 5:
            lvl_b3rd = 10
            c_3rd = '#74DF00'
        elif w_3rd > 5 and w_3rd <= 15:
            lvl_b3rd = 35
            c_3rd = '#FFFF00'
        elif w_3rd > 15 and w_3rd <= 25:
            lvl_b3rd = 60
            c_3rd = '#FF8000'
        elif w_3rd >= 25:
            lvl_b3rd = 90
            c_3rd = '#FA5858'

        lvl_webs = 5
        if w_webs >= 0 and w_webs < 2:
            lvl_webs = 10
            c_webs = '#74DF00'
        elif w_webs >= 2 and w_webs <= 5:
            lvl_webs = 35
            c_webs = '#FFFF00'
        elif w_webs > 5 and w_webs <= 10:
            lvl_webs = 60
            c_webs = '#FF8000'
        elif w_webs >= 10:
            lvl_webs = 90
            c_webs = '#FA5858'

        lvl_ip = 5
        if w_ip > 0:
            lvl_ip = 90
            c_ip = '#FA5858'

        lvl_url = 5
        if w_url >= 0 and w_url < 10:
            lvl_url = 10
            c_url = '#74DF00'
        elif w_url >= 10 and w_url <= 80:
            lvl_url = 35
            c_url = '#FFFF00'
        elif w_url > 80 and w_url <= 150:
            lvl_url = 60
            c_url = '#FF8000'
        elif w_url >= 150:
            lvl_url = 90
            c_url = '#FA5858'

        lvl_bkdr = 5
        if w_bkdr > 0:
            lvl_bkdr = 90
            c_bkdr = '#FA5858'

        lvl_hpass = 5
        if w_hpass > 0:
            lvl_hpass = 90
            c_hpass = '#FA5858'

        lvl_email = 5
        if w_email >= 0 and w_email < 10:
            lvl_email = 10
            c_email = '#74DF00'
        elif w_email >= 10 and w_email <= 20:
            lvl_email = 35
            c_email = '#FFFF00'
        elif w_email > 20 and w_email <= 100:
            lvl_email = 60
            c_email = '#FF8000'
        elif w_email >= 100:
            lvl_email = 90
            c_email = '#FA5858'

        lvl_malptr = 5
        if w_malptr == 0:
            lvl_malptr = 10
            c_malptr = '#74DF00'
        elif w_malptr > 0 and w_malptr <= 100:
            lvl_malptr = 35
            c_malptr = '#FFFF00'
        elif w_malptr > 100 and w_malptr <= 500:
            lvl_malptr = 60
            c_malptr = '#FF8000'
        elif w_malptr >= 500:
            lvl_malptr = 90
            c_malptr = '#FA5858'

        figure(figsize=(13, 10))

        height = [lvl_pass, lvl_ssl, lvl_ssh, lvl_cfg, lvl_db, lvl_shel, lvl_bfile, lvl_b3rd, lvl_webs, lvl_ip, lvl_url,
                  lvl_bkdr, lvl_hpass, lvl_email, lvl_malptr]
        bars = ('Admin passwords', 'SSl Cert', 'SSH', 'Config files', 'DB files', 'Shell scripts', 'Misc', '3rd Party',
                'Web servers', 'IP addresses', 'Urls', 'backdoor', 'Hardcoded passwords', 'Emails',
                'Malicious patterns')
        y_pos = np.arange(len(bars))
        listbar = plt.barh(y_pos, height, .50)
        plt.yticks(y_pos, bars)
        plt.xticks([10, 35, 60, 90], ['clean', 'low risk', 'medium risk', 'high risk'])
        listbar[0].set_color(c_pass)
        listbar[1].set_color(c_ssl)
        listbar[2].set_color(c_ssh)
        listbar[3].set_color(c_cfg)
        listbar[4].set_color(c_db)
        listbar[5].set_color(c_shel)
        listbar[6].set_color(c_bfile)
        listbar[7].set_color(c_3rd)
        listbar[8].set_color(c_webs)
        listbar[9].set_color(c_ip)
        listbar[10].set_color(c_url)
        listbar[11].set_color(c_bkdr)
        listbar[12].set_color(c_hpass)
        listbar[13].set_color(c_email)
        listbar[14].set_color(c_malptr)

        red_patch = mpatches.Patch(color='#FA5858', label='High Risk')
        orange_patch = mpatches.Patch(color='#FF8000', label='Medium Risk')
        yellow_patch = mpatches.Patch(color='#FFFF00', label='Low Risk')
        green_patch = mpatches.Patch(color='#74DF00', label='Clean')
        plt.legend(handles=[red_patch, orange_patch, yellow_patch, green_patch], loc='lower center',
                   bbox_to_anchor=(.5, 1.005), fancybox=True, shadow=True, ncol=5)
        plt.savefig('static/temp_results/static_lvl.png', dpi=100)
        plt.close()

        fp_lvl2 = open("static/temp_results/static_findings.txt", "w")


        cnt_high = 0
        cnt_med = 0
        cnt_low = 0
        cnt_clean = 0
        for high in height:
            fp_lvl2.writelines(str(high) + "\n")
            if high == 90:
                cnt_high = cnt_high + 1
            if high == 60:
                cnt_med = cnt_med + 1
            if high == 35:
                cnt_low = cnt_low + 1
            if high == 5 or high == 10:
                cnt_clean = cnt_clean + 1

        fp_lvl = open("static/temp_results/levels.txt", "w")
        fp_lvl.writelines(str(cnt_high) + "\n")
        fp_lvl.writelines(str(cnt_med) + "\n")
        fp_lvl.writelines(str(cnt_low) + "\n")
        fp_lvl.writelines(str(cnt_clean))
        fp_lvl.close()




        pas_f = "pswd:" + str(indx_pasf)
        ssl_f = "ssl:" + str(indx_sslf)
        ssh_f = "ssh:" + str(indx_sshf)
        cfg_f = "cfg:" + str(indx_cfgf)
        db_f = "db:" + str(indx_dbf)
        sh_sc = "scripts:" + str(indx_sscr)
        m_bin = "misc bin:" + str(indx_mbin)
        imp_bin = "imp binaries:" + str(indx_ibin)
        ws_f = "web servers:" + str(indx_ws)
        ip_n = "ip:" + str(indx_ip)
        url_n = "url:" + str(indx_url)
        email_n = "email:" + str(indx_email)
        bkdr_n = "backdoor:" + str(indx_bkdr)
        hpas = "passwd:" + str(indx_hpas)

        graph2 = [pas_f, ssl_f, ssh_f, cfg_f, db_f, sh_sc, m_bin, imp_bin, ws_f, ip_n, url_n, email_n, bkdr_n, hpas]
        x_axis2 = []
        y_axis2 = []
        lpi2 = 0
        for ptrn4 in graph2:
            ptrn_valc2 = graph2[lpi2].split(':')
            x_axis2.append(ptrn_valc2[0])
            y_axis2.append(ptrn_valc2[1])
            lpi2 += 1

        int_y2 = []
        val_c2 = 0
        for val2 in y_axis2:
            int_y2.append(int(y_axis2[val_c2]))
            val_c2 += 1

        y_pos2 = np.arange(len(x_axis2))
        plt.figure(2)
        plt.bar(y_pos2, int_y2, align='center', alpha=1)
        plt.xticks(y_pos2, x_axis2)
        plt.xlabel('Extracted Credentials', fontsize=22)
        plt.ylabel('Count', fontsize=22)
        plt.suptitle('Extracted Credentials of Firmware Binary Under Test', fontsize=30, color='C0')
        fig = matplotlib.pyplot.gcf()
        fig.set_size_inches(22, 10)
        fig.savefig('media/Credentials.png', dpi=100)
        plt.close()

        pdf.add_page()
        pdf.set_font(font_h, 'B', size=18)
        pdf.set_text_color(rh, gh, bh)
        pdf.cell(0, 10, txt="Summary of Findings\n".format(1), ln=1, align="C")
        pdf.cell(0, 5, txt="", ln=1, align="L")

        pdf.image("media/Credentials.png", x=0, y=30, w=210)
        # pdf.ln(1000)  # move 85 down
        pdf.cell(0, 10, txt="", ln=1)
        pdf.image("media/patterns.png", x=0, y=130, w=210)
        pdf.cell(0, 10, txt="", ln=10)

        pdf.output("static/temp_results/static.pdf")

        rm_cmdp1 = "rm media/Credentials.png"
        os.system(rm_cmdp1)
        rm_cmdp2 = "rm media/patterns.png"
        os.system(rm_cmdp2)
        rm_cmdcr = "rm media/Credentials.txt"
        os.system(rm_cmdcr)

        send_logs("Static analysis has been completed\n")

def add_bookmarks(no_of_pages_in_codeAnalysis):
    
    pdf_object = open("static/temp_results/Report1.pdf", "rb")  # rb stands for read binary
    output = PdfFileWriter()
    input = PdfFileReader(pdf_object)

    input_numpages = input.getNumPages()

    # basically just copy the input file
    for i in range(input_numpages):
        output.addPage(input.getPage(i))  # insert page in the output file


    # region PARENT 1 Bookmarks
    parent_1 = output.addBookmark('FEAST', 0)  # add parent bookmark
    bookmarks_dic_1 = {
        "Executive Summary": 0,
        "Introduction": 0,
        "Evaluation": 1,
        "Reliability of Results": 1,
    }

    for k, v in bookmarks_dic_1.items():
        output.addBookmark(k, v + 1, parent_1)  # add child bookmarks
    # endregion

    # region PARENT 2 Bookmarks
    parent_2 = output.addBookmark('Security Assessment Criteria', 3)  # add parent bookmark
    bookmarks_dic_2 = {
        "Identified Vulnerable Fields from Static Analysis": 2,
        "Identified Vulnerabilities from Code Analysis": 4,
        "Cumulative Vulnerability Count from Static and Code Analysis": 4
    }

    for k, v in bookmarks_dic_2.items():
        output.addBookmark(k, v + 1, parent_2)  # add child bookmarks
    # endregion

    # region PARENT 3 Bookmarks
    parent_3 = output.addBookmark("Firmware Under Test", 6)  # add parent bookmark
    # bookmarks_dic_3 = {
    #     "Identified Vulnerable Fields from Static Analysis": 2,
    #     "Identified Vulnerabilities from Code Analysis": 4,
    #     "Cumulative Vulnerability Count from Static and Code Analysis": 4
    # }
    #
    # for k, v in bookmarks_dic_3.items():
    #     output.addBookmark(k, v + 1, parent_3)  # add child bookmarks
    # endregion

    # region PARENT 4 Bookmarks
    parent_4 = output.addBookmark("Summary of Findings", 7)  # add parent bookmark
    bookmarks_dic_4 = {
        "Security Status of Firmware Under Test": 6,
        "Code Analysis of Firmware Binary Under Test": 6,
        "Static Analysis of Firmware Binary Under Test": 7
    }

    for k, v in bookmarks_dic_4.items():
        output.addBookmark(k, v + 1, parent_4)  # add child bookmarks
    # endregion
    # region PARENT 5 Bookmarks
    parent_5 = output.addBookmark("Details of Code Analysis Findings", 9)  # add parent bookmark
    # endregion

    # region PARENT 6 Bookmarks
    parent_6 = output.addBookmark("Details of Static Analysis Findings", 9 + no_of_pages_in_codeAnalysis)  # add parent bookmark
    # endregion

    # region PARENT 7 Bookmarks
    parent_7 = output.addBookmark("Recommendations", -1)  # add parent bookmark
    # endregion

    # region PARENT 8 Bookmarks
    parent_8 = output.addBookmark("Conclusion", -1)  # add parent bookmark
    # endregion


    outputstream = open('static/temp_results/Report.pdf', 'wb')  # creating result
    output.write(outputstream)  # writing to result pdf
    outputstream.close()  # closing result


@shared_task(bind=True)
def dynamic(self):
    time.sleep(1)
    send_logs('Starting Code Analysis')
    arr9 = ['dropbear', 'dropbearkey', 'ghost_libc', 'dropbearconvert', 'QCMAP_Web_CLIENT', 'ssh', 'sshd', 'scp',
            'sftp', 'tftp', 'telnet', 'telnetd', 'openssl',
            'tddp', 'rpaed', 'libcontainer_aiffc.so', 'libcontainer_flac.so', 'libcontainer_id3.so',
            'libcontainer_mp3.so', 'libcontainer_mpeg4.so', 'libcontainer_ogg.so', 'libcontainer_snd.so',
            'libcontainer_wav.so', 'libdecoder_aac.so', 'libdecoder_au.so', 'libdecoder_flac.so', 'libdecoder_mp3.so',
            'libdecoder_pcm.so', 'brctl', 'libdecoder_vorbis.so', 'busybox', 'dbclient']


    prog = []
    for root, dirs, files in os.walk("media/ext_firm/"):
        for file in files:
            for db in arr9:
                if file.endswith(db):
                    cmdl = 'ls -l ' + root + '/' + file
                    out_p = subprocess.check_output(cmdl, shell=True, stderr=subprocess.STDOUT)
                    out_str = str(out_p)
                    sp_out = out_str.split(" ")
                    if sp_out[0] == 'b\'-rwxrwxrwx':
                        prog.append(file)


    for root, dirs, files in os.walk("media/ext_firm/"):
        for file in files:
            for db in arr9:
                if file.endswith(db):
                    cmdl = 'ls -l ' + root + '/' + file
                    out_p = subprocess.check_output(cmdl, shell=True, stderr=subprocess.STDOUT)
                    out_str = str(out_p)
                    sp_out = out_str.split(" ")
                    if sp_out[0] == 'b\'-rwxrwxrwx':
                        send_logs("Analyzing " + str(file) + " executable")
                        res_stack = sim_check(root, file)
                        send_logs(str(file) + " has been decomplied")
                        send_logs("Performing the code analysis on " + str(file))
                        fp1 = open("static/temp_results/temp_code/" + file + ".stack", "w")
                        for stack in res_stack:
                            fp1.write(stack)
                            fp1.write("\n")

                        obs_funcs = obsolete_funcs(file)
                        fp2 = open("static/temp_results/temp_code/" + file + ".obs", "w")
                        for obs in obs_funcs:
                            fp2.write(obs)
                            fp2.write("\n")

                        bufs = bufAnalysis(file)
                        fp3 = open("static/temp_results/temp_code/" + file + ".bufs", "w")
                        for buf in bufs:
                            fp3.write(buf)
                            fp3.write("\n")

                        args = badParse(file)
                        fp4 = open("static/temp_results/temp_code/" + file + ".args", "w")
                        for arg in args:
                            fp4.write(arg)
                            fp4.write("\n")

    send_logs('Code analysis has been completed')


@shared_task(bind=True)
def report(self):
    time.sleep(1)
    pdf = FPDF(orientation='P', unit='mm', format='A4')
    pdf.add_page()

    rh = 0
    gh = 102
    bh = 204

    rh2 = 51
    gh2 = 153
    bh2 = 255

    rt = 0
    gt = 0
    bt = 0

    font_h = "Times"
    font_h2 = "Times"
    font_t = "Times"
    fsize_h = 14
    fsize_h2 = 12
    fsize_t = 12

    indx_h = 0
    indx_h2 = 0
    ln = 0

    files_arr = []
    for (dirpath, dirnames, files) in os.walk("static/temp_results/temp_code/"):
        files_arr.extend(files)
        break

    indx_obs = 0
    indx_stack = 0
    indx_arg = 0
    indx_buf = 0

    flag_obs = 0
    flag_stack = 0
    flag_arg = 0
    flag_buf = 0

    for obs_fun in files_arr:
        nm = str(obs_fun).split(".")
        if str(nm[-1]) == "obs":
            path1 = "static/temp_results/temp_code/" + obs_fun
            fp1 = open(path1, "r")

            lines = fp1.readlines()
            for line in lines:
                obs_line = line.strip()
                if flag_obs == 0:
                    flag_obs = 1
                    pdf.set_font(font_h, 'B', size=fsize_h)
                    pdf.set_text_color(rh, gh, bh)
                    indx_h += 1
                    pdf.cell(0, 10, txt="Detail of Code Analysis Findings\n".format(ln), ln=1, align="C")
                    
                    pdf.cell(0, 10, txt=str(indx_h) + ". Obsolete Functions\n".format(ln), ln=1, align="C")
                    ln += 1
                    pdf.set_font(font_t, size=fsize_t)
                    pdf.set_text_color(rt, gt, bt)
                    pdf.multi_cell(0, 5,
                                   txt="Use of obsolete and vulnerable functions can cause security attacks. Listed below are the detected obsolete functions from the decompiled C code:",
                                   align="J")
                    pdf.cell(0, 5, txt="".format(ln), ln=1, align="L")

                    pdf.set_text_color(rh2, gh2, bh2)
                    pdf.set_font(font_h2, size=fsize_h2)
                    pdf.cell(0, 5, txt="How to patch?\n".format(ln), ln=1, align="L")
                    ln += 1
                    pdf.set_text_color(rt, gt, bt)
                    pdf.set_font(font_t, size=fsize_t)
                    pdf.multi_cell(0, 5,
                                   txt=" The alternative functions available at the Microsoft site should be used.",
                                   align="J")
                    pdf.cell(0, 5, txt="".format(ln), ln=1, align="L")

                    ln += 1

                    pdf.set_text_color(rh2, gh2, bh2)
                    pdf.set_font(font_h2, size=fsize_h2)
                    pdf.cell(0, 5, txt="Findings\n".format(ln), ln=1, align="L")
                    ln += 1

                pdf.set_font(font_t, size=fsize_t)
                pdf.set_text_color(rt, gt, bt)

                indx_obs += 1
                pdf.cell(0, 5, txt=str(indx_obs) + ". " + obs_line + "\n".format(ln), ln=1, align="L")
                ln += 1

    for mal_stack in files_arr:
        nm2 = str(mal_stack).split(".")
        if str(nm2[-1]) == "stack":
            path2 = "static/temp_results/temp_code/" + mal_stack
            fp2 = open(path2, "r")

            lines = fp2.readlines()
            for line in lines:
                stack_line = line.strip()

                if flag_stack == 0:
                    flag_stack = 1
                    pdf.set_font(font_h, 'B', size=fsize_h)
                    pdf.set_text_color(rh, gh, bh)
                    indx_h += 1
                    pdf.cell(0, 10, txt=str(indx_h) + ". Malicious Code Stacks\n".format(ln), ln=1, align="C")
                    ln += 1
                    pdf.set_font(font_t, size=fsize_t)
                    pdf.set_text_color(rt, gt, bt)
                    pdf.multi_cell(0, 5,
                                   txt="Some vendors reuse the open source libraries containg the vulnerabilities. Listed below are the detected malicious code stacks leading to different vulnerailities: ",
                                   align="J")
                    pdf.cell(0, 5, txt="".format(ln), ln=1, align="L")

                    pdf.set_text_color(rh2, gh2, bh2)
                    pdf.set_font(font_h2, size=fsize_h2)
                    pdf.cell(0, 5, txt="How to patch?\n".format(ln), ln=1, align="L")
                    ln += 1
                    pdf.set_text_color(rt, gt, bt)
                    pdf.set_font(font_t, size=fsize_t)
                    pdf.multi_cell(0, 5,
                                   txt=" They should not exist in the firmware.",
                                   align="J")
                    pdf.cell(0, 5, txt="".format(ln), ln=1, align="L")

                    ln += 1

                    pdf.set_text_color(rh2, gh2, bh2)
                    pdf.set_font(font_h2, size=fsize_h2)
                    pdf.cell(0, 5, txt="Findings\n".format(ln), ln=1, align="L")
                    ln += 1

                pdf.set_font(font_t, size=fsize_t)
                pdf.set_text_color(rt, gt, bt)

                indx_stack += 1
                pdf.cell(0, 5, txt=str(indx_stack) + ". " + stack_line + "\n".format(ln), ln=1, align="L")
                ln += 1

    for bad_arg in files_arr:
        nm3 = str(bad_arg).split(".")
        if str(nm3[-1]) == "args":
            path3 = "static/temp_results/temp_code/" + bad_arg
            fp3 = open(path3, "r")

            lines = fp3.readlines()
            for line in lines:
                arg_line = line.strip()
                if flag_arg == 0:
                    flag_arg = 1
                    pdf.set_font(font_h, 'B', size=fsize_h)
                    pdf.set_text_color(rh, gh, bh)
                    indx_h += 1
                    pdf.cell(0, 10, txt=str(indx_h) + ". Bad Argument Parsing Leading to CVE-2019-12103\n".format(ln),
                             ln=1, align="C")
                    ln += 1
                    pdf.set_font(font_t, size=fsize_t)
                    pdf.set_text_color(rt, gt, bt)
                    pdf.multi_cell(0, 5,
                                   txt="Passing the untrusted user inputs directly to the functions which runs system-level commands, is very dangerous. It takes C string for its execution which is usually created by snprintf () function. For example, when popen() is called with format specifier without verifying the user inputs, custom C string can be passed to popen(). It results in the unauthenticated telnet access leading to CVE-2019-12103.",
                                   align="J")
                    pdf.cell(0, 5, txt="".format(ln), ln=1, align="L")

                    pdf.set_text_color(rh2, gh2, bh2)
                    pdf.set_font(font_h2, size=fsize_h2)
                    pdf.cell(0, 5, txt="How to patch?\n".format(ln), ln=1, align="L")
                    ln += 1
                    pdf.set_text_color(rt, gt, bt)
                    pdf.set_font(font_t, size=fsize_t)
                    pdf.multi_cell(0, 5,
                                   txt=" Validation should be applied while argument parsing.",
                                   align="J")
                    pdf.cell(0, 5, txt="".format(ln), ln=1, align="L")

                    ln += 1

                    pdf.set_text_color(rh2, gh2, bh2)
                    pdf.set_font(font_h2, size=fsize_h2)
                    pdf.cell(0, 5, txt="Findings\n".format(ln), ln=1, align="L")
                    ln += 1

                pdf.set_font(font_t, size=fsize_t)
                pdf.set_text_color(rt, gt, bt)

                indx_arg += 1
                pdf.cell(0, 5, txt=str(indx_arg) + ". " + arg_line + "\n".format(ln), ln=1, align="L")
                ln += 1

    for buf_over in files_arr:
        nm4 = str(buf_over).split(".")
        if str(nm4[-1]) == "bufs":
            path4 = "static/temp_results/temp_code/" + buf_over
            fp4 = open(path4, "r")

            lines = fp4.readlines()
            for line in lines:
                buf_line = line.strip()
                if flag_buf == 0:
                    flag_buf = 1
                    pdf.set_font(font_h, 'B', size=fsize_h)
                    pdf.set_text_color(rh, gh, bh)
                    indx_h += 1
                    pdf.cell(0, 10,
                             txt=str(indx_h) + ". Static Memory Allocations leading to Buffer Overruns\n".format(ln),
                             ln=1, align="C")
                    ln += 1
                    pdf.set_font(font_t, size=fsize_t)
                    pdf.set_text_color(rt, gt, bt)
                    pdf.multi_cell(0, 5,
                                   txt="With the help of buffer overrun attacks, attacker can execute custom functionality. This is because of smashing the stack, return statement is executed. The attacker can insert arbitrary code at somewhere and is able to execute it when he has control over the return address. With the overwriting of return address, the arguments of the exploitable functions can be altered. The basic cause of these buffer overruns is the static allocation of memory for buffers instead of dynamic allocation. Listed below are the detected static memory allocations leading to buffer overruns:",
                                   align="J")
                    pdf.cell(0, 5, txt="".format(ln), ln=1, align="L")

                    pdf.set_text_color(rh2, gh2, bh2)
                    pdf.set_font(font_h2, size=fsize_h2)
                    pdf.cell(0, 5, txt="How to patch?\n".format(ln), ln=1, align="L")
                    ln += 1
                    pdf.set_text_color(rt, gt, bt)
                    pdf.set_font(font_t, size=fsize_t)
                    pdf.multi_cell(0, 5,
                                   txt=" Memory should be dynamically allocated.",
                                   align="J")
                    pdf.cell(0, 5, txt="".format(ln), ln=1, align="L")

                    ln += 1

                    pdf.set_text_color(rh2, gh2, bh2)
                    pdf.set_font(font_h2, size=fsize_h2)
                    pdf.cell(0, 5, txt="Findings\n".format(ln), ln=1, align="L")
                    ln += 1

                pdf.set_font(font_t, size=fsize_t)
                pdf.set_text_color(rt, gt, bt)

                indx_buf += 1
                pdf.cell(0, 5, txt=str(indx_buf) + ". " + buf_line + "\n".format(ln), ln=1, align="L")
                ln += 1


    x_axis = ['Obsolete Functions', 'Malicious Code Stacks', 'Bad Arguments', 'Static Memory Allocations']
    y_axis = [indx_obs, indx_stack, indx_arg, indx_buf]

    y_pos = np.arange(len(x_axis))
    int_y = []
    val_c = 0
    for val in y_axis:
        int_y.append(int(y_axis[val_c]))
        val_c += 1

    plt.figure(3)
    plt.bar(y_pos, int_y, align='center', alpha=1)
    plt.xticks(y_pos, x_axis)
    plt.ylabel('Number of Findings', fontsize=22)

    fig = matplotlib.pyplot.gcf()
    fig.set_size_inches(22, 24)
    fig.savefig('static/temp_results/code.png', dpi=100)
    plt.close()

    w_obs = indx_obs * 10
    w_stack = indx_stack * 27
    w_arg = indx_arg
    w_buf = indx_buf * 8

    lvl_obs = 10
    lvl_stack = 10
    lvl_arg = 10
    lvl_buf = 10

    c_obs = '#74DF00'
    c_stack = '#74DF00'
    c_arg = '#74DF00'
    c_buf = '#74DF00'

    if w_obs > 1 and w_obs <= 50:
        lvl_obs = 35
        c_obs = '#FFFF00'
    elif w_obs > 50 and w_obs <= 100:
        lvl_obs = 60
        c_obs = '#FF8000'
    elif w_obs > 100:
        lvl_obs = 90
        c_obs = '#FA5858'

    if w_stack > 0 and w_stack <= 300:
        lvl_stack = 35
        c_stack = '#FFFF00'
    elif w_stack > 300 and w_stack <= 500:
        lvl_stack = 60
        c_stack = '#FF8000'
    elif w_stack > 500:
        lvl_stack = 90
        c_stack = '#FA5858'

    if w_buf > 0 and w_buf <= 1000:
        lvl_buf = 35
        c_buf = '#FFFF00'
    elif w_buf > 1000 and w_buf <= 3000:
        lvl_buf = 60
        c_buf = '#FF8000'
    elif w_buf > 3000:
        lvl_buf = 90
        c_buf = '#FA5858'

    w_arg = 0
    if w_arg == 0:
        lvl_arg = 10
        c_arg = '#74DF00'
    else:
        lvl_arg = 90
        c_arg = '#FA5858'

    figure(figsize=(17, 10))
    height = [lvl_obs, lvl_stack, lvl_arg, lvl_buf]
    fp_c = open("static/temp_results/code_findings.txt", "w")
    for high in height:
        fp_c.writelines(str(high) + "\n")

    fp_c.close()




    bars = ('Obsolete Functions', 'Malicious Code Stacks', 'Bad Arguments', 'Static Memory Allocations')
    y_pos = np.arange(len(bars))
    listbar = plt.barh(y_pos, height, .30)
    plt.yticks(y_pos, bars)
    plt.xticks([10, 35, 60, 90], ['clean', 'low risk', 'medium risk', 'high risk'])
    listbar[0].set_color(c_obs)
    listbar[1].set_color(c_stack)
    listbar[2].set_color(c_arg)
    listbar[3].set_color(c_buf)
    red_patch = mpatches.Patch(color='#FA5858', label='High Risk')
    orange_patch = mpatches.Patch(color='#FF8000', label='Medium Risk')
    yellow_patch = mpatches.Patch(color='#FFFF00', label='Low Risk')
    green_patch = mpatches.Patch(color='#74DF00', label='Clean')
    plt.legend(handles=[red_patch, orange_patch, yellow_patch, green_patch], loc='lower center',
               bbox_to_anchor=(.5, 1.005), fancybox=True, shadow=True, ncol=5)
    plt.savefig('static/temp_results/code_lvl.png', dpi=100)
    plt.close()


    cnt_high = 0
    cnt_med = 0
    cnt_low = 0
    cnt_clean = 0
    for high in height:
        if high == 90:
            cnt_high = cnt_high + 1
        if high == 60:
            cnt_med = cnt_med + 1
        if high == 35:
            cnt_low = cnt_low + 1
        if high == 5 or high == 10:
            cnt_clean = cnt_clean + 1

    fp_lvl = open("static/temp_results/levels.txt", "r")
    vals = fp_lvl.readlines()
    val_h = int(vals[0]) + cnt_high
    val_m = int(vals[1]) + cnt_med
    val_l = int(vals[2]) + cnt_low
    val_c = int(vals[3]) + cnt_clean

    # Pie chart, where the slices will be ordered and plotted counter-clockwise:
    labels = 'High Risk Vuln', 'Medium Risk Vuln', 'Low Risk Vuln', 'Clean'
    sizes = [val_h, val_m, val_l, val_c]
    fp_pie = open("static/temp_results/pie.txt", "w")
    for sz in sizes:
        fp_pie.writelines(str(sz) + "\n")
    colors = ["#FA5858", "#FF8000", "#FFFF00", "#74DF00"]
    explode = (0.1, 0, 0, 0)  # only "explode" the 2nd slice (i.e. 'Hogs')

    fig1, ax1 = plt.subplots()
    ax1.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%',
            shadow=True, startangle=90)
    ax1.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    # plt.title('Security Status of Firmware Under Test', y=-0.13, fontsize=18, color='#0066CC')
    plt.savefig('static/temp_results/pie.png', dpi=100)

    pdf.add_page()
    pdf.set_font(font_h, 'B', size=18)
    pdf.set_text_color(rh, gh, bh)
    pdf.cell(0, 10, txt="Summary of Code Analysis\n".format(1), ln=1, align="C")
    pdf.cell(0, 5, txt="", ln=1, align="L")

    pdf.image("static/temp_results/code.png", x=0, y=30, w=210)
    pdf.output("static/temp_results/codeAnalysis.pdf")

    pdf2 = FPDF(orientation='P', unit='mm', format='A4')
    pdf2.add_page()
    pdf2.set_font(font_h, 'B', size=25)
    pdf2.set_text_color(rh, gh, bh)
    pdf2.multi_cell(0, 5, txt="Summary of Findings", align="C")
    pdf2.image("static/temp_results/pie.png", x=25, y=30, w=150)
    pdf2.set_font(font_h, 'B', size=15)
    pdf2.set_y(135)
    pdf2.cell(0, 10, txt="Security Status of Firmware Under Test", align="C")
    pdf2.image("static/temp_results/code_lvl.png", x=0, y=150, w=210)
    pdf2.set_y(265)
    pdf2.cell(0, 10, txt="Code Analysis of Firmware Binary Under Test", align="C")
    pdf2.add_page()
    pdf2.image("static/temp_results/static_lvl.png", x=0, y=10, w=210, h=230)
    pdf2.set_y(225)
    pdf2.cell(0, 10, txt="Static Analysis of Firmware Binary Under Test", align="C")
    pdf2.output("static/temp_results/graphs.pdf")

    pdf3 = FPDF(orientation='P', unit='mm', format='A4')
    pdf3.add_page()
    pdf3.set_font(font_h, 'B', size=25)
    pdf3.set_text_color(rh, gh, bh)
    pdf3.multi_cell(0, 5, txt="FEAST : Firmware Under Test", align="C")
    pdf3.set_font(font_h, 'B', size=15)

    ln =1
    pdf3.set_y(40)
    pdf3.set_font(font_t, size=fsize_t)
    pdf3.set_text_color(rt, gt, bt)
    pdf3.multi_cell(0, 5, txt=" The firmware binary analyzed by toolkit FEAST alongwith the timestamp in Coordinated Universal Time (UTC), for security analysis and report generation is added below. Further on, the sections cover the illustrative representation of Summary of findings, which inludes the security status of firmware binary undertest as well as the findings from the static and code analysis. Afterwards, the report covers the detail of findings from the Code Analysis and Static Analysis. Finally, we conclude the report by providing our Security Recommendations.",
                                   align="L")
    

    fp_fn_in = open('media/name.txt', 'r')
    name_str = fp_fn_in.readlines()
    fp_fn_in.close()

    
    ln +=1
    pdf3.set_y(80)
    pdf3.set_text_color(rh, gh, bh)
    pdf3.set_font(font_h2, size=fsize_h2)
    pdf3.cell(0, 10, txt=str(name_str[0])+'\n'.format(ln), ln=1, align="C")
    ln +=1
    pdf3.cell(0, 10, txt='Timestamp: '+str(datetime.now(pytz.timezone("UTC"))), align="C")
    pdf3.output("static/temp_results/name_timestamp.pdf")

    
    merger = PyPDF2.PdfFileMerger()
    if lvl_obs == 10 and lvl_stack == 10 and lvl_arg == 10 and lvl_buf == 10:
        merger.merge(position=0, fileobj="static/Recommendations.pdf")
        merger.merge(position=0, fileobj="static/temp_results/static.pdf")
        merger.merge(position=0, fileobj="static/temp_results/graphs.pdf")
        merger.merge(position=0, fileobj="static/temp_results/name_timestamp.pdf")
        merger.merge(position=0, fileobj="static/s1.pdf")
        merger.merge(position=0, fileobj="static/feast.pdf")
        merger.merge(position=0, fileobj="static/cover.pdf")
    else:
        merger.merge(position=0, fileobj="static/Recommendations.pdf")
        merger.merge(position=0, fileobj="static/temp_results/static.pdf")
        merger.merge(position=0, fileobj="static/temp_results/codeAnalysis.pdf")
        merger.merge(position=0, fileobj="static/temp_results/graphs.pdf")
        merger.merge(position=0, fileobj="static/temp_results/name_timestamp.pdf")
        merger.merge(position=0, fileobj="static/s1.pdf")
        merger.merge(position=0, fileobj="static/feast.pdf")
        merger.merge(position=0, fileobj="static/cover.pdf")

    merger.write(open("static/temp_results/Report1.pdf", "wb"))

    pdf_object = open("static/temp_results/codeAnalysis.pdf", "rb")  # rb stands for read binary
    output = PdfFileWriter()
    input = PdfFileReader(pdf_object)

    input_numpages = input.getNumPages()

    add_bookmarks(int(input_numpages))




    send_logs('Report has been generated')
    try:
        cmd4 = "rm static/temp_results/temp_code/*"
        os.system(cmd4)
        cmd5 = "rm static/temp_results/code.png"
        os.system(cmd5)
        cmd6 = "rm static/temp_results/codeAnalysis.pdf"
        os.system(cmd6)
        cmd7 = "rm static/temp_results/code_lvl.png"
        os.system(cmd7)
        cmd8 = "rm static/temp_results/graphs.pdf"
        os.system(cmd8)
        cmd9 = "rm static/temp_results/levels.txt"
        os.system(cmd9)
        cmd10 = "rm static/temp_results/pie.png"
        os.system(cmd10)
        cmd11 = "rm static/temp_results/static.pdf"
        os.system(cmd11)
        cmd12 = "rm static/temp_results/static_lvl.png"
        os.system(cmd12)
        cmd13 = "rm static/temp_results/name_timestamp.pdf"
        os.system(cmd13)
        cmd14 = "rm media/name.txt"
        os.system(cmd14)
    except:
        pass

    fp_pie = open('static/temp_results/pie.txt', 'r')
    pie_vals = fp_pie.readlines()
    send_logs('pie:'+str(pie_vals[0])+':'+str(pie_vals[1])+':'+str(pie_vals[2])+':'+str(pie_vals[3]))

    fp_static = open('static/temp_results/static_findings.txt', 'r')
    static_vals = fp_static.readlines()
    send_logs('static:' + str(static_vals[0]) + ':' + str(static_vals[1]) + ':' + str(static_vals[2]) + ':' +
              str(static_vals[3]) + ':' + str(static_vals[4]) + ':' + str(static_vals[5]) + ':' + str(static_vals[6])
              + ':' + str(static_vals[7]) + ':' + str(static_vals[8]) + ':' + str(static_vals[9])
              + ':' + str(static_vals[10]) + ':' + str(static_vals[11]) + ':' + str(static_vals[12])
              + ':' + str(static_vals[13]) + ':' + str(static_vals[14]))

    fp_code2 = open('static/temp_results/code_findings.txt', 'r')
    code_valsf = fp_code2.readlines()
    send_logs('code:' + str(code_valsf[0]) + ':' + str(code_valsf[1]) + ':' + str(code_valsf[2]) + ':' + str(code_valsf[3]))

    time.sleep(1)
    cmd13 = "rm static/temp_results/code_findings.txt"
    os.system(cmd13)
    cmd14 = "rm static/temp_results/pie.txt"
    os.system(cmd14)
    cmd15 = "rm static/temp_results/static_findings.txt"
    os.system(cmd15)

    



def send_logs(logs):
    async_to_sync(channel_layer.group_send)(
        'chats', {
            "type": 'send_message_to_frontend',
            "message": logs
        }
    )


