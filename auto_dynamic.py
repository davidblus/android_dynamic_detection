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
import json
from mass_static_analysis import genMD5
from MobSF.utils import getADB
import signal
from StaticAnalyzer.views.android.manifest_analysis import get_manifest
from StaticAnalyzer.views.android.manifest_analysis import manifest_data as get_manifest_data
from StaticAnalyzer.views.shared_func import Unzip
import subprocess
import threading
import time
import traceback

from Analysis_x_logcat.analysis import analysis_x_logcat

BASE_DIR = '.'
DEBUGING = False
DEBUGING_NUMS = 5
UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')
ORIGIN_DOWNLOAD_DIR = os.path.join(BASE_DIR, 'downloads')
DYNAMIC_TOOL_DIR = os.path.join(os.path.join(BASE_DIR, 'DynamicAnalyzer'), 'tools')
STATIC_TOOL_DIR = os.path.join(os.path.join(BASE_DIR, 'StaticAnalyzer'), 'tools')


def get_static_info(file_path, file_md5):

    unzip_dir = os.path.join(UPLOAD_DIR, file_md5)
    unzip_result = Unzip(file_path, unzip_dir)
    print 'len(unzip_result):', len(unzip_result)
    
    apk_path = os.path.join(unzip_dir, 'app.apk')
    shutil.copy(file_path, apk_path)
    
    manifest_xml = get_manifest(unzip_dir, STATIC_TOOL_DIR, '', True)
    print 'manifest_xml:', manifest_xml
    
    manifest_data = get_manifest_data(manifest_xml)
    print 'manifest_data["packagename"]:', manifest_data['packagename']
    print 'manifest_data["application_name"]:', manifest_data['application_name']
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
    app_dir = os.path.join(UPLOAD_DIR, file_md5)
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

# monkey script 测试
def monkey_script_test(adb, app_info):
    monkey_script_pattern = '''
    type=user
    count=10
    speed=1.0
    start data >>
    captureDispatchPointer(0,0,0,200,600,1,1,-1,1,1,0,0)
    captureDispatchPointer(0,0,1,200,600,1,1,-1,1,1,0,0)
    UserWait(1000)
    captureDispatchPointer(0,0,0,400,600,1,1,-1,1,1,0,0)
    captureDispatchPointer(0,0,1,400,600,1,1,-1,1,1,0,0)
    UserWait(1000)
    captureDispatchPointer(0,0,0,600,600,1,1,-1,1,1,0,0)
    captureDispatchPointer(0,0,1,600,600,1,1,-1,1,1,0,0)
    UserWait(1000)
    captureDispatchPointer(0,0,0,200,800,1,1,-1,1,1,0,0)
    captureDispatchPointer(0,0,1,200,800,1,1,-1,1,1,0,0)
    UserWait(1000)
    captureDispatchPointer(0,0,0,600,1000,1,1,-1,1,1,0,0)
    captureDispatchPointer(0,0,1,600,1000,1,1,-1,1,1,0,0)
    UserWait(3000)
    LaunchActivity({packagename}, {mainactivity})
    UserWait(5000)
    Drag({screen_x_right},{screen_y_middle},{screen_x_left},{screen_y_middle},70)
    UserWait({drag_wait})
    Drag({screen_x_right},{screen_y_middle},{screen_x_left},{screen_y_middle},70)
    UserWait({drag_wait})
    Drag({screen_x_right},{screen_y_middle},{screen_x_left},{screen_y_middle},70)
    UserWait({drag_wait})
    Drag({screen_x_right},{screen_y_middle},{screen_x_left},{screen_y_middle},70)
    UserWait({drag_wait})
    Drag({screen_x_right},{screen_y_middle},{screen_x_left},{screen_y_middle},70)
    UserWait({drag_wait})
    Drag({screen_x_right},{screen_y_middle},{screen_x_left},{screen_y_middle},70)
    UserWait({drag_wait})
    Drag({screen_x_right},{screen_y_middle},{screen_x_left},{screen_y_middle},70)
    UserWait({drag_wait})
    Drag({screen_x_right},{screen_y_middle},{screen_x_left},{screen_y_middle},70)
    UserWait({drag_wait})
    Drag({screen_x_right},{screen_y_middle},{screen_x_left},{screen_y_middle},70)
    UserWait({drag_wait})
    Drag({screen_x_right},{screen_y_middle},{screen_x_left},{screen_y_middle},70)
    UserWait({drag_wait})
    Drag({screen_x_right},{screen_y_middle},{screen_x_left},{screen_y_middle},70)
    UserWait({drag_wait})
    Drag({screen_x_right},{screen_y_middle},{screen_x_left},{screen_y_middle},70)
    UserWait({drag_wait})
    captureDispatchPointer(0,0,0,{screen_x_middle},100,1,1,-1,1,1,0,0)
    captureDispatchPointer(0,0,1,{screen_x_middle},100,1,1,-1,1,1,0,0)
    captureDispatchPointer(0,0,0,{screen_x_middle},200,1,1,-1,1,1,0,0)
    captureDispatchPointer(0,0,1,{screen_x_middle},200,1,1,-1,1,1,0,0)
    captureDispatchPointer(0,0,0,{screen_x_middle},300,1,1,-1,1,1,0,0)
    captureDispatchPointer(0,0,1,{screen_x_middle},300,1,1,-1,1,1,0,0)
    captureDispatchPointer(0,0,0,{screen_x_middle},400,1,1,-1,1,1,0,0)
    captureDispatchPointer(0,0,1,{screen_x_middle},400,1,1,-1,1,1,0,0)
    captureDispatchPointer(0,0,0,{screen_x_middle},500,1,1,-1,1,1,0,0)
    captureDispatchPointer(0,0,1,{screen_x_middle},500,1,1,-1,1,1,0,0)
    captureDispatchPointer(0,0,0,{screen_x_middle},600,1,1,-1,1,1,0,0)
    captureDispatchPointer(0,0,1,{screen_x_middle},600,1,1,-1,1,1,0,0)
    captureDispatchPointer(0,0,0,{screen_x_middle},700,1,1,-1,1,1,0,0)
    captureDispatchPointer(0,0,1,{screen_x_middle},700,1,1,-1,1,1,0,0)
    captureDispatchPointer(0,0,0,{screen_x_middle},800,1,1,-1,1,1,0,0)
    captureDispatchPointer(0,0,1,{screen_x_middle},800,1,1,-1,1,1,0,0)
    captureDispatchPointer(0,0,0,{screen_x_middle},900,1,1,-1,1,1,0,0)
    captureDispatchPointer(0,0,1,{screen_x_middle},900,1,1,-1,1,1,0,0)
    captureDispatchPointer(0,0,0,{screen_x_middle},1000,1,1,-1,1,1,0,0)
    captureDispatchPointer(0,0,1,{screen_x_middle},1000,1,1,-1,1,1,0,0)
    captureDispatchPointer(0,0,0,{screen_x_middle},1100,1,1,-1,1,1,0,0)
    captureDispatchPointer(0,0,1,{screen_x_middle},1100,1,1,-1,1,1,0,0)
    captureDispatchPointer(0,0,0,{screen_x_middle},1200,1,1,-1,1,1,0,0)
    captureDispatchPointer(0,0,1,{screen_x_middle},1200,1,1,-1,1,1,0,0)
    UserWait(1000)
    captureDispatchPress(4)
    captureDispatchPress(4)
    captureDispatchPress(4)
    '''
    drag_wait = 750
    packagename = app_info['packagename']
    mainactivity = app_info['mainactivity']
    if mainactivity.startswith('.'):
        mainactivity = packagename + mainactivity
    screen_x_right = 750
    screen_y_middle = 640
    screen_x_left = 50
    screen_x_middle = 400
    
    monkey_script_data = monkey_script_pattern.format(drag_wait=drag_wait, 
        packagename=packagename, mainactivity=mainactivity, 
        screen_x_right=screen_x_right, screen_y_middle=screen_y_middle, 
        screen_x_left=screen_x_left, screen_x_middle=screen_x_middle)
    
    monkey_script_file_name = os.path.join(os.path.join(UPLOAD_DIR, app_info['file_md5']), 'monkey_script.txt')
    with open(monkey_script_file_name, 'w') as f:
        f.write(monkey_script_data)
    
    subprocess.call([adb,
                     "-s",
                     get_identifier(),
                     "push",
                     monkey_script_file_name,
                     "/data/local/tmp"])
    subprocess.call([adb,
                     "-s",
                     get_identifier(),
                     "shell",
                     "monkey", "-f", 
                     "/data/local/tmp/monkey_script.txt", "1"])
    print u'\n[INFO] 跳过初始化界面'
    return

def auto_app_test(adb, app_info):
    print u'\n[INFO] 开始自动化测试...'
    
    # monkey script 测试，用于进入初始化界面
    monkey_script_test(adb, app_info)
    
    packagename = app_info['packagename']
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
    subprocess.call([adb,
                     "-s",
                     get_identifier(),
                     "pull",
                     "/data/data/de.robv.android.xposed.installer/log/error.log",
                     download_dir + "x_logcat_temp.txt"])
    print "\n[INFO] Downloading Droidmon API Monitor Logcat logs"
    # TODO: 下载其他有用文件
    return

Is_Downloading = True
def download_logs_thread(adb, download_dir):
    if not os.path.isdir(download_dir):
        os.makedirs(download_dir)
    global Is_Downloading
    while Is_Downloading:
        download_logs(adb, download_dir)
        log_path = os.path.join(download_dir, 'x_logcat.txt')
        log_temp_path = os.path.join(download_dir, 'x_logcat_temp.txt')
        if os.path.exists(log_path):
            log_size = os.path.getsize(log_path)
            log_temp_size = os.path.getsize(log_temp_path)
            if log_size < log_temp_size:
                shutil.copy(log_temp_path, log_path)
        else:
            shutil.copy(log_temp_path, log_path)
        os.remove(log_temp_path)
        time.sleep(10)
    return

# 运行该 apk 文件，获取运行时特征并存储在 '该文件路径' + '_info_/' 目录中，
# 因此调用该函数时需要先检查以上目录是否存在，如果存在则认为已经运行过该 apk 文件。
def dynamic_main(file_path):
    file_md5 = genMD5(file_path)
    print 'file_md5:', file_md5
    
    # download_dir = ORIGIN_DOWNLOAD_DIR + app_info['file_md5'] + '/'
    download_dir = file_path + '_info_/'
    
    try:
        app_info = get_static_info(file_path, file_md5)
        
        # 开始动态分析
        adb = getADB(DYNAMIC_TOOL_DIR)
        init_environment(adb)
        
        set_web_proxy(app_info['file_md5'])
        
        connect_device(adb)
        
        
        # Change True to support non-activity components
        install_and_run(DYNAMIC_TOOL_DIR, app_info['apk_path'], app_info['packagename'], app_info['mainactivity'], True)

        # 开启下载 log 线程
        global Is_Downloading
        Is_Downloading = True
        t = threading.Thread(target=download_logs_thread, args=(adb, download_dir, ))
        t.start()

        time.sleep(40)
        
        auto_app_test(adb, app_info)
        
        # 停止代理服务器，另一个线程会把网络传输数据保存到 UPLOAD_DIR 对应的文件夹中的 urls, WebTraffic.txt, requestdb 文件。
        Proxy('', '', '', '')
        
        # 关闭下载 log 线程
        Is_Downloading = False
        t.join()
        
        time.sleep(3)
        
        # 复制 apk 运行时访问的 url 到结果目录
        shutil.copy(os.path.join(os.path.join(UPLOAD_DIR, app_info['file_md5']), 'urls'), os.path.join(download_dir, 'urls'))
        
        result = analysis_x_logcat(download_dir + 'x_logcat.txt', app_info)
        print u'分析结果目录：', download_dir
    except Exception as e:
        result = {}
        # Install Error           表示安装 apk 文件时报错。
        # Parsing Manifest Error  表示解析 AndroidManifest.xml 文件时报错。
        if str(e) == 'Install Error':
            Proxy('', '', '', '')
            time.sleep(3)
            os.makedirs(download_dir)
        elif str(e) == 'Parsing Manifest Error':
            os.makedirs(download_dir)
        else:
            print traceback.format_exc()
    
    # 由于临时文件比较大，当硬盘空间不足时，则删除临时文件，比如：UPLOAD_DIR, 
    shutil.rmtree(os.path.join(UPLOAD_DIR, file_md5))
    
    return result

def get_features_from_dir(dir_path):
    run_times = 0
    for root, dirs, files in os.walk(dir_path):
        if root.endswith('_info_'):
            continue
        for name in files:
            if os.path.exists(os.path.join(root, name + '_info_')):
                continue
            file_name = os.path.join(root, name)
            print u'\n正在运行文件：', file_name
            dynamic_main(file_name)
            print u'文件运行完毕：', file_name, '\n'
            run_times = run_times + 1
            if DEBUGING:
                if run_times == DEBUGING_NUMS:
                    return
    return

def print_x_log_analysis_result(result):
    print u'\n检测到敏感行为：'
    print json.dumps(result['sensitives'], indent=4, ensure_ascii=False)
    
    print u'\n检测到漏洞：'
    print json.dumps(result['vulnerabilities'], indent=4, ensure_ascii=False)
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

def test_get_features():
    print u'请输入包含apk文件的目录绝对路径：'
    dir_path = raw_input()
    if dir_path.startswith('"') and dir_path.endswith('"'):
        dir_path = dir_path[1:-1]
    print 'dir_path:', dir_path
    get_features_from_dir(dir_path)
    return

if __name__ == '__main__':
    try:
        # test_dynamic()
        test_get_features()
    except Exception as err:
        print traceback.format_exc()
    os.kill(os.getpid(), signal.SIGTERM)
