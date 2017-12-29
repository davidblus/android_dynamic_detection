# -*- coding: utf8 -*-
"""Shared Functions for Android Dynamic Analyzer"""

import subprocess
import os
import time
import traceback
from django.conf import settings
from DynamicAnalyzer.pyWebProxy.pywebproxy import Proxy
from MobSF.utils import PrintException, getADB

def connect(toolsdir):
    """Connect to VM/Device"""
    print "\n[INFO] Connecting to VM/Device"
    try:
        adb = getADB(toolsdir)
        subprocess.call([adb, "kill-server"])
        subprocess.call([adb, "start-server"])
        print "\n[INFO] ADB Started"
        wait(5)
        print "\n[INFO] Connecting to VM/Device"
        result = subprocess.call([adb, "connect", get_identifier()])
        if settings.ANDROID_DYNAMIC_ANALYZER == "MobSF_REAL_DEVICE" and result != 0:
            subprocess.call([adb, "tcpip", str(settings.DEVICE_ADB_PORT)])
            subprocess.call([adb, "connect", get_identifier()])
        subprocess.call([adb, "-s", get_identifier(), "wait-for-device"])
        print "\n[INFO] Mounting"
        if settings.ANDROID_DYNAMIC_ANALYZER == "MobSF_REAL_DEVICE":
            subprocess.call([adb, "-s", get_identifier(), "shell",
                             "su", "-c", "mount", "-o", "rw,remount,rw", "/system"])
        else:
            subprocess.call([adb, "-s", get_identifier(), "shell",
                             "su", "-c", "mount", "-o", "rw,remount,rw", "/system"])
            # This may not work for VMs other than the default MobSF VM
            subprocess.call([adb, "-s", get_identifier(), "shell", "mount",
                             "-o", "rw,remount", "-t", "rfs", "/dev/block/sda6", "/system"])
    except:
        print traceback.format_exc()
        PrintException("[ERROR]  Connecting to VM/Device")

def sign_apk(apk_path):
    signed_apk_path = os.path.join(os.path.dirname(apk_path), 'app_signed.apk')
    subprocess.call(['jarsigner', '-keystore', 'davidblus_android.keystore', 
                     '-storepass', 'davidblus', '-signedjar', signed_apk_path, 
                     apk_path, 'davidblus_android.keystore'])
    return signed_apk_path

def install_and_run(toolsdir, apk_path, package, launcher, is_activity):
    """Install APK and Run it"""
    print "\n[INFO] Starting App for Dynamic Analysis"
    # try:
    adb = getADB(toolsdir)
    print "\n[INFO] Installing APK"
    install_result = subprocess.check_output([adb, "-s", get_identifier(),
                     "install", "-r", apk_path])
    print install_result
    # 如果是未签名的错误，则对其进行签名并安装，
    # 签名命令示例：jarsigner -verbose -keystore davidblus_android.keystore -storepass davidblus -signedjar app_signed.apk app.apk davidblus_android.keystore
    if 'INSTALL_PARSE_FAILED_NO_CERTIFICATES' in install_result:
        signed_apk_path = sign_apk(apk_path)
        install_result = subprocess.check_output([adb, "-s", get_identifier(),
                         "install", "-r", signed_apk_path])
        print install_result
    if 'Success' not in install_result:
        raise Exception('Install Error')
    if is_activity:
        run_app = package + "/" + launcher
        print "\n[INFO] Launching APK Main Activity"
        subprocess.call([adb, "-s", get_identifier(),
                         "shell", "am", "start", "-n", run_app])
    else:
        print "\n[INFO] App Doesn't have a Main Activity"
        # Handle Service or Give Choice to Select in Future.
    print "[INFO] Testing Environment is Ready!"
    # except:
    #     PrintException("[ERROR]  Starting App for Dynamic Analysis")


def wait(sec):
    """Wait in Seconds"""
    print "\n[INFO] Waiting for " + str(sec) + " seconds..."
    time.sleep(sec)


def web_proxy(apk_dir, ip_address, port):
    """Run MITM Proxy"""
    print "\n[INFO] Starting Web Proxy"
    try:
        Proxy(ip_address, port, apk_dir, "on")
    except:
        PrintException("[ERROR] Starting Web Proxy")


def get_res():
    """Get Screen Resolution or Device or VM"""
    print "\n[INFO] Getting Screen Resolution"
    try:
        toolsdir = os.path.join(
            settings.BASE_DIR, 'DynamicAnalyzer/tools/')  # TOOLS DIR
        adb = getADB(toolsdir)
        resp = subprocess.check_output(
            [adb, "-s", get_identifier(), "shell", "dumpsys", "window"])
        resp = resp.split("\n")
        res = ""
        for line in resp:
            if "mUnrestrictedScreen" in line:
                res = line
                break
        res = res.split("(0,0)")[1]
        res = res.strip()
        res = res.split("x")
        if len(res) == 2:
            return res[0], res[1]
            # width, height
        return "", ""
    except:
        PrintException("[ERROR] Getting Screen Resolution")
        return "", ""


def get_identifier():
    """Get Device Type"""
    try:
        if settings.ANDROID_DYNAMIC_ANALYZER == "MobSF_REAL_DEVICE":
            return settings.DEVICE_IP + ":" + str(settings.DEVICE_ADB_PORT)
        elif settings.ANDROID_DYNAMIC_ANALYZER == "MobSF_AVD":
            return 'emulator-' + str(settings.AVD_ADB_PORT)
        else:
            return settings.VM_IP + ":" + str(settings.VM_ADB_PORT)
    except:
        PrintException(
            "[ERROR] Getting ADB Connection Identifier for Device/VM")
