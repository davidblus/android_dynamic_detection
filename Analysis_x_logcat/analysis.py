# coding: utf-8

import json
import sys
reload(sys)
sys.setdefaultencoding('utf8')

from vulnerability_detection import transfer_func_to_vul

# hooks.json 文件路径
FILE_HOOKS_JSON = 'Analysis_x_logcat/hooks.json'

#  api调用->敏感行为 规则
FUNCTION_TO_SENSITIVE_BEHAVIOR = [
    {'function_list': [('android.content.pm.PackageManager', 'checkPermission')], 
        'name': u'申请权限'}, 
    {'function_list': [('android.content.pm.IPackageManager', 'checkPermission')], 
        'name': u'申请权限'}, 
    {'function_list': [('android.telephony.TelephonyManager', 'getSimSerialNumber')], 
        'name': u'查看本机SIM卡序列号'}, 
    {'function_list': [('android.telephony.TelephonyManager', 'getLine1Number')], 
        'name': u'查看本机号码'}, 
    {'function_list': [('android.telephony.TelephonyManager', 'getDeviceSoftwareVersion')], 
        'name': u'查看手机软件版本号'}, 
    {'function_list': [('android.telephony.TelephonyManager', 'getDeviceId')], 
        'name': u'查看本机IMEI'}, 
    {'function_list': [('android.telephony.TelephonyManager', 'getSubscriberId')], 
        'name': u'查看本机IMSI'}, 
    {'function_list': [('android.telephony.TelephonyManager', 'getSimCountryIso')], 
        'name': u'查看SIM卡的国家码'}, 
    {'function_list': [('android.telephony.TelephonyManager', 'getCallState')], 
        'name': u'查看手机来电状态'}, 
    {'function_list': [('android.telephony.TelephonyManager', 'getNetworkCountryIso')], 
        'name': u'查看网络所在的国家代码'}, 
    {'function_list': [('android.telephony.TelephonyManager', 'getNetworkOperator')], 
        'name': u'查看mobile country code + mobile network code'}, 
    {'function_list': [('android.telephony.TelephonyManager', 'getNetworkOperatorName')], 
        'name': u'查看手机运营商'}, 
    {'function_list': [('android.app.admin.DevicePolicyManager', 'isAdminActive')], 
        'name': u'操作设备管理器'}, 
    {'function_list': [('android.app.admin.DevicePolicyManager', 'lockNow')], 
        'name': u'锁屏'}, 
    {'function_list': [('java.lang.reflect.Method', 'invoke')], 
        'name': u'调用了java反射机制'}, 
    {'function_list': [('java.lang.Class', 'getMethod', [(1, 'setMobileDataEnabled')])], 
        'name': u'开启移动网络连接'}, 
    {'function_list': [('java.lang.Class', 'getDeclaredMethod', [(1, 'setMobileDataEnabled')])], 
        'name': u'开启移动网络连接'}, 
    {'function_list': [('android.net.wifi.WifiInfo', 'getMacAddress')], 
        'name': u'查看wifi的MAC地址'}, 
    {'function_list': [('android.net.wifi.WifiManager', 'setWifiEnabled')], 
        'name': u'开启wifi'}, 
    {'function_list': [('android.os.Debug', 'isDebuggerConnected')], 
        'name': u'检测了是否被jdb调试'}, 
    {'function_list': [('java.lang.Runtime', 'exec')], 
        'name': u'调用底层linux程序'}, 
    {'function_list': [('android.telephony.PhoneNumberUtils', 'getNumberFromIntent')], 
        'name': u'拨打电话'}, 
    {'function_list': [('android.telephony.SmsManager', 'sendTextMessage')], 
        'name': u'发送短信'}, 
    {'function_list': [('android.telephony.SmsManager', 'sendDataMessage')], 
        'name': u'发送短信'}, 
    {'function_list': [('android.telephony.SmsManager', 'sendMultipartTextMessage')], 
        'name': u'发送彩信'}, 
    {'function_list': [('android.telephony.SmsMessage', 'createFromPdu'), 
                       ('android.content.IntentFilter', 'setPriority'), 
                       ('android.content.BroadcastReceiver', 'abortBroadcast')], 
        'name': u'拦截短信'}, 
    {'function_list': [('android.telephony.TelephonyManager', 'getCellLocation')], 
        'name': u'查看地理位置信息'}, 
    {'function_list': [('android.location.Location', 'getLatitude')], 
        'name': u'查看地理位置信息'}, 
    {'function_list': [('android.telephony.TelephonyManager', 'getSimOperatorName')], 
        'name': u'查看运营商信息'}, 
    {'function_list': [('android.media.AudioRecord', 'startRecording')], 
        'name': u'录音'}, 
    {'function_list': [('android.hardware.Camera', 'startPreview')], 
        'name': u'拍照摄像'}, 
    {'function_list': [('android.hardware.Camera', 'open')], 
        'name': u'拍照摄像'}, 
    {'function_list': [('android.media.MediaRecorder', 'start')], 
        'name': u'摄像'}, 
    {'function_list': [('android.content.pm.PackageManager', 'setComponentEnabledSetting')], 
        'name': u'隐藏图标'}, 
    {'function_list': [('javax.mail.Transport', 'sendMessage')], 
        'name': u'发送邮件'}, 
    {'function_list': [('android.widget.Gallery', 'setOnItemSelectedListener')], 
        'name': u'查看相册'}, 
    {'function_list': [('android.accounts.AccountManager', 'getAccounts')], 
        'name': u'查看用户账号信息'}, 
    {'function_list': [('android.accounts.AccountManager', 'getAccountsByType')], 
        'name': u'查看用户账号信息'}, 
    {'function_list': [('android.content.pm.PackageParser', 'parsePackage')], 
        'name': u'安装应用程序'}, 
    {'function_list': [('dalvik.system.BaseDexClassLoader', 'findLibrary')], 
        'name': u'动态类加载'}, 
    {'function_list': [('android.os.Process', 'killProcess')], 
        'name': u'结束进程行为'}, 
    {'function_list': [('android.app.ActivityManager', 'killBackgroundProcesses')], 
        'name': u'结束进程行为'}, 
    {'function_list': [('android.content.pm.PackageManager', 'deletePackage')], 
        'name': u'卸载应用程序'}, 
    {'function_list': [('android.content.pm.PackageManager', 'installPackage')], 
        'name': u'安装应用程序'}, 
    {'function_list': [('android.content.pm.PackageManager', 'getInstalledPackages')], 
        'name': u'查看已安装包名'}, 
    {'function_list': [('android.app.ActivityManager', 'getRunningTasks')], 
        'name': u'查看 TOP Activity'}, 
    {'function_list': [('android.app.ActivityManager', 'getRunningAppProcesses')], 
        'name': u'查看运行时进程信息'}, 
    {'function_list': [('android.app.ActivityManager', 'RunningServiceInfo')], 
        'name': u'查看运行时服务'}, 
    {'function_list': [('android.os.SystemProperties', 'get')], 
        'name': u'查看Android系统属性'}, 
]

def load_x_file(x_file_name, package_name):
    globals = {
        'false': False, 
        'true': True, 
    }
    with open(x_file_name) as x_file:
        x_lines = x_file.readlines()
    data = []
    droidmon_prefix = 'Droidmon-apimonitor-'
    for x_line in x_lines:
        if x_line.startswith(droidmon_prefix + package_name):
            value_dict = eval(x_line[len(droidmon_prefix + package_name) + 1:], globals)
            data.append(value_dict)
    return data

def init_hook_datas(hook_datas, package_name):
    for i, hook_data in enumerate(hook_datas['hookConfigs']):
        hook_datas['hookConfigs'][i][package_name] = []
    return hook_datas

def make_hooks_datas(x_datas, package_name):
    with open(FILE_HOOKS_JSON) as hook_file:
        hook_datas = json.load(hook_file)
    hook_datas = init_hook_datas(hook_datas, package_name)
    for i, hook_data in enumerate(hook_datas['hookConfigs']):
        for x_data in x_datas:
            if x_data['class'] == hook_data['class_name'] and x_data['method'] == hook_data['method']:
                hook_datas['hookConfigs'][i][package_name].append(x_data)
    return hook_datas

def count_function(hook_datas, package_name):
    function_list = []
    for hook_data in hook_datas['hookConfigs']:
        if hook_data[package_name]:
            function_list.append({'class': hook_data['class_name'], 
                'method': hook_data['method'], 'call_list': hook_data[package_name]})
    return function_list

def exist_sen_func(class_func, function_real_list):
    for function_real in function_real_list:
        if class_func[0] == function_real['class'] and class_func[1] == function_real['method']:
            # 无参数的情况
            if len(class_func) == 2:
                return True
            # TODO: 考虑有参数的情况，参数列表从0开始，意思是需要匹配的参数是个字典，key从0开始。
            # 例如规则：{'function_list': [('android.content.pm.PackageManager', 'checkPermission', {'0': '匹配第一个参数', '1': '匹配第二个参数'})], 'name': u'申请权限'}, 
    return False

def transfer_func_to_sen(function_real_list):
    sensitives = []
    for func_to_sen in FUNCTION_TO_SENSITIVE_BEHAVIOR:
        flag = True
        for func_rule in func_to_sen['function_list']:
            if not exist_sen_func(func_rule, function_real_list):
                flag = False
                break;
        if flag:
            sensitives.append(func_to_sen['name'])
    return sensitives

def save_file(file_name, data):
    with open(file_name, 'w') as file:
        file.write(json.dumps(data, indent=4, ensure_ascii=False))
    return

def analysis_x_logcat(x_file_name, app_info):
    package_name = app_info['packagename']
    
    # func_timeflow 表示以时间顺序记录的函数调用列表。 TODO: 供后续制定以时间序列调用api的规则，进而检测分析。
    func_timeflow = load_x_file(x_file_name, package_name)
    save_file(x_file_name + '_timeflow_list.json', func_timeflow)
    
    # hook_datas 表示数据处理过程中的中间结果。
    hook_datas = make_hooks_datas(func_timeflow, package_name)
    # save_file(x_file_name + '_hook_result.json', hook_datas)
    
    # func_statistic 表示以api为关键字的函数调用列表。 TODO: 供后续制定以api调用详细信息的规则，进而检测分析。
    func_statistic = count_function(hook_datas, package_name)
    save_file(x_file_name + '_count_function.json', func_statistic)
    
    # 根据 api调用->敏感行为 规则，查出其具有的敏感行为列表。
    sensitives = transfer_func_to_sen(func_statistic)
    save_file(x_file_name + '_sensitives.json', sensitives)
    
    # 根据 api调用->漏洞 规则，查出其具有的漏洞列表。
    vulnerabilities = transfer_func_to_vul(func_statistic, app_info)
    save_file(x_file_name + '_vulnerabilities.json', vulnerabilities)

    return sensitives

def test():
    global FILE_HOOKS_JSON
    FILE_HOOKS_JSON = 'hooks.json'
    print u'请输入x_logcat文件的绝对路径：'
    file_name = raw_input()
    if file_name.startswith('"') and file_name.endswith('"'):
        file_name = file_name[1:-1]
    print u'请输入包名：'
    package_name = raw_input()
    result = analysis_x_logcat(file_name, package_name)
    print u'\n检测到漏洞：'
    for temp in result:
        print temp 
    return

if __name__ == '__main__':
    test()