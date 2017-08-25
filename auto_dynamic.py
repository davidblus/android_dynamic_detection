# -*- coding: utf8 -*-

import os
os.environ.update({"DJANGO_SETTINGS_MODULE": "MobSF.settings"})
import shutil
import MobSF.settings as SETTINGS

from DynamicAnalyzer.pyWebProxy.pywebproxy import Proxy
from DynamicAnalyzer.views.android.android_avd import avd_load_wait
from DynamicAnalyzer.views.android.android_avd import refresh_avd
from DynamicAnalyzer.views.android.android_dyn_shared import connect
from DynamicAnalyzer.views.android.android_dyn_shared import install_and_run
from DynamicAnalyzer.views.android.android_dyn_shared import web_proxy
from DynamicAnalyzer.views.android.android_dyn_shared import get_identifier
from DynamicAnalyzer.views.android.android_virtualbox_vm import refresh_vm
from mass_static_analysis import genMD5
from MobSF.utils import getADB
import signal
from StaticAnalyzer.views.android.manifest_analysis import get_manifest
from StaticAnalyzer.views.android.manifest_analysis import manifest_data as get_manifest_data
from StaticAnalyzer.views.shared_func import Unzip
import subprocess
import time
import traceback

from Analysis_x_logcat.analysis import analysis_x_logcat

BASE_DIR = './'
UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads/')
DOWNLOAD_DIR = os.path.join(BASE_DIR, 'downloads/')
DYNAMIC_TOOL_DIR = os.path.join(BASE_DIR, 'DynamicAnalyzer/tools/')
STATIC_TOOL_DIR = os.path.join(BASE_DIR, 'StaticAnalyzer/tools/')


def get_static_info(file_path):

    file_md5 = genMD5(file_path)
    print 'file_md5:', file_md5
    
    unzip_dir = UPLOAD_DIR + file_md5 + '/'
    unzip_result = Unzip(file_path, unzip_dir)
    print 'len(unzip_result):', len(unzip_result)
    
    apk_path = unzip_dir + 'app.apk'
    shutil.copy(file_path, apk_path)
    
    manifest_xml = get_manifest(unzip_dir, STATIC_TOOL_DIR, '', True)
    print 'manifest_xml:', manifest_xml
    
    manifest_data = get_manifest_data(manifest_xml)
    print 'manifest_data["packagename"]:', manifest_data['packagename']
    print 'manifest_data["mainactivity"]:', manifest_data['mainactivity']
    
    manifest_data['file_md5'] = file_md5
    manifest_data['apk_path'] = apk_path
    return manifest_data

def init_environment(adb):
    Proxy('', '', '', '')
    if SETTINGS.ANDROID_DYNAMIC_ANALYZER == "MobSF_REAL_DEVICE":
        print "\n[INFO] MobSF will perform Dynamic Analysis on real Android Device"
    elif SETTINGS.ANDROID_DYNAMIC_ANALYZER == "MobSF_AVD":
        # adb, avd_path, reference_name, dup_name, emulator
        refresh_avd(adb, SETTINGS.AVD_PATH, SETTINGS.AVD_REFERENCE_NAME,
                    SETTINGS.AVD_DUP_NAME, SETTINGS.AVD_EMULATOR)
    else:
        # Refersh VM
        refresh_vm(SETTINGS.UUID, SETTINGS.SUUID, SETTINGS.VBOX)
    return

def set_web_proxy(file_md5):
    app_dir = UPLOAD_DIR + file_md5 + '/'
    if SETTINGS.ANDROID_DYNAMIC_ANALYZER == "MobSF_AVD":
        proxy_ip = '127.0.0.1'
    else:
        proxy_ip = SETTINGS.PROXY_IP  # Proxy IP
    port = str(SETTINGS.PORT)  # Proxy Port
    web_proxy(app_dir, proxy_ip, port)
    return

def connect_device(adb):
    # AVD only needs to wait, vm needs the connect function
    if SETTINGS.ANDROID_DYNAMIC_ANALYZER == "MobSF_AVD":
        if not avd_load_wait(adb):
            print "\n[WARNING] ADB Load Wait Failed"
            exit()
    else:
        connect(DYNAMIC_TOOL_DIR)
    return

def auto_app_test(adb, packagename):
    print u'\n[INFO] 开始自动化测试...'
    # monkey 测试，输出太多，重定向输出
    p = subprocess.Popen([adb, '-s', get_identifier(), 'shell', 
                'monkey', '-p', packagename, 
                '--ignore-crashes', '--ignore-timeouts', 
                '--monitor-native-crashes', 
                '-v', '-v', '-v', '1000'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # 设置超时检查
    start_time = time.time()
    while True:
        if p.poll() is not None:
            #useless_out, useless_err = p.communicate()
            break
        if time.time() - start_time > 60:
            p.terminate()
            break
        time.sleep(0.5)
    
    # TODO: 添加其他测试方法
    return

def download_logs(adb, download_dir):
    if not os.path.isdir(download_dir):
        os.makedirs(download_dir)
    subprocess.call([adb,
                     "-s",
                     get_identifier(),
                     "pull",
                     "/data/data/de.robv.android.xposed.installer/log/error.log",
                     download_dir + "x_logcat.txt"])
    print "\n[INFO] Downloading Droidmon API Monitor Logcat logs"
    # TODO: 下载其他有用文件
    return

def dynamic_main(file_path):
    app_info = get_static_info(file_path)
    
    # 开始动态分析
    adb = getADB(DYNAMIC_TOOL_DIR)
    init_environment(adb)
    
    set_web_proxy(app_info['file_md5'])
    
    connect_device(adb)
    
    # Change True to support non-activity components
    install_and_run(DYNAMIC_TOOL_DIR, app_info['apk_path'], app_info['packagename'], app_info['mainactivity'], True)
    time.sleep(60)
    
    auto_app_test(adb, app_info['packagename'])
    
    download_dir = DOWNLOAD_DIR + app_info['file_md5'] + '/'
    download_logs(adb, download_dir)
    
    result = analysis_x_logcat(download_dir + 'x_logcat.txt', app_info)
    print u'分析结果目录：', download_dir
    return result

def print_x_log_analysis_result(result):
    print u'\n检测到敏感行为：'
    for temp in result['sensitives']:
        print temp
    
    print u'\n检测到漏洞：'
    for temp in result['vulnerabilities']:
        print temp
    return

def test_dynamic():
    print u'请输入被检测apk文件的绝对路径：'
    file_path = raw_input()
    if file_path.startswith('"') and file_path.endswith('"'):
        file_path = file_path[1:-1]
    print 'file_path:', file_path
    result = dynamic_main(file_path)
    print_x_log_analysis_result(result)
    return

if __name__ == '__main__':
    try:
        test_dynamic()
    except Exception as err:
        print traceback.format_exc()
    os.kill(os.getpid(), signal.SIGTERM)
