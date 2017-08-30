# coding: utf-8

import json
import sys
reload(sys)
sys.setdefaultencoding('utf8')

from Global import add_api_position_single_api
from vulnerability_detection import transfer_func_to_vul

# hooks.json 文件路径
FILE_HOOKS_JSON = 'Analysis_x_logcat/hooks.json'

#  api调用->敏感行为 规则
FUNCTION_TO_SENSITIVE_BEHAVIOR_RULES_FULL_MATCH = [
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
        'name': u'获取本机来电状态'},
    {'function_list': [('android.telephony.TelephonyManager', 'getNetworkCountryIso')], 
        'name': u'查看网络所在的国家代码'}, 
    {'function_list': [('android.telephony.TelephonyManager', 'getNetworkOperator')], 
        'name': u'查看移动设备国家代码和移动设备网络代码'}, 
    {'function_list': [('android.telephony.TelephonyManager', 'getNetworkOperatorName')], 
        'name': u'查看本机运营商'},
    {'function_list': [('android.app.admin.DevicePolicyManager', 'isAdminActive')], 
        'name': u'操作设备管理器'}, 
    {'function_list': [('android.app.admin.DevicePolicyManager', 'lockNow')], 
        'name': u'锁屏'}, 
    {'function_list': [('java.lang.reflect.Method', 'invoke')], 
        'name': u'调用java反射机制'},
    {'function_list': [('java.lang.Class', 'getMethod', {'0': 'setMobileDataEnabled'})], 
        'name': u'开启移动网络连接'}, 
    {'function_list': [('java.lang.Class', 'getDeclaredMethod', {'0': 'setMobileDataEnabled'})], 
        'name': u'开启移动网络连接'}, 
    {'function_list': [('android.net.wifi.WifiInfo', 'getMacAddress')], 
        'name': u'查看wifi的MAC地址'}, 
    {'function_list': [('android.net.wifi.WifiManager', 'setWifiEnabled')], 
        'name': u'开启wifi'}, 
    {'function_list': [('android.os.Debug', 'isDebuggerConnected')], 
        'name': u'检测了是否被jdb调试'}, 
    {'function_list': [('java.lang.Runtime', 'exec', {'0': 'su'})], 
        'name': u'请求Root权限'}, 
    {'function_list': [('java.lang.Runtime', 'exec')], 
        'name': u'调用底层linux程序'}, 
    {'function_list': [('android.telephony.PhoneNumberUtils', 'getNumberFromIntent')], 
        'name': u'拨打电话'}, 
    {'function_list': [('android.telephony.SmsManager', 'sendTextMessage')], 
        'name': u'发送短信'}, 
    {'function_list': [('android.telephony.SmsManager', 'sendDataMessage')], 
        'name': u'发送短信'}, 
    {'function_list': [('android.telephony.SmsManager', 'sendMultipartTextMessage')], 
        'name': u'发送短信'}, 
    {'function_list': [('android.content.IntentFilter', 'addAction', {'0': 'android.provider.Telephony.SMS_RECEIVED'}), 
                       ('android.content.IntentFilter', 'setPriority', {'0': '2147483647'}), ], 
        'name': u'短信接收器注册'}, 
    {'function_list': [('android.os.Bundle', 'get', {'0': 'pdus’'}), 
                       ('android.content.BroadcastReceiver', 'abortBroadcast'), ], 
        'name': u'拦截短信'}, 
    {'function_list': [('android.telephony.SmsMessage', 'createFromPdu'), 
                       ('android.content.IntentFilter', 'setPriority'), 
                       ('android.content.BroadcastReceiver', 'abortBroadcast')], 
        'name': u'拦截短信'}, 
    {'function_list': [('android.telephony.TelephonyManager', 'getCellLocation')], 
        'name': u'获取蜂窝位置信息'}, 
    {'function_list': [('android.location.Location', 'getLatitude')], 
        'name': u'查看地理位置信息'}, 
    {'function_list': [('android.telephony.TelephonyManager', 'getSimOperatorName')], 
        'name': u'查看运营商信息'}, 
    {'function_list': [('android.media.AudioRecord', 'startRecording')], 
        'name': u'录音行为'}, 
    {'function_list': [('android.hardware.Camera', 'startPreview')], 
        'name': u'拍照摄像'}, 
    {'function_list': [('android.hardware.Camera', 'open')], 
        'name': u'拍照摄像'}, 
    {'function_list': [('android.media.MediaRecorder', 'start')], 
        'name': u'摄像'}, 
    {'function_list': [('android.content.pm.PackageManager', 'setComponentEnabledSetting', {'1': '2', '2': '1'})], 
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
    {'function_list': [('android.content.Intent', 'setDataAndType', {'1': 'application/vnd.android.package-archive'})], 
        'name': u'安装应用程序'}, 
    {'function_list': [('android.content.pm.PackageManager', 'getInstalledPackages')], 
        'name': u'获取已安装包名'}, 
    {'function_list': [('android.app.ActivityManager', 'getRunningTasks')], 
        'name': u'查看TopActivity'}, 
    {'function_list': [('android.app.ActivityManager', 'getRunningAppProcesses')], 
        'name': u'获取运行时进程信息'}, 
    {'function_list': [('android.app.ActivityManager', 'RunningServiceInfo')], 
        'name': u'查看运行时服务'}, 
    {'function_list': [('android.os.SystemProperties', 'get')], 
        'name': u'查看Android系统属性'}, 
]
FUNCTION_TO_SENSITIVE_BEHAVIOR_RULES_URI_CONTAIN = [
    {'function': ('android.content.ContentResolver', 'registerContentObserver', {'0': 'content://sms'}), 
        'name': u'短信监听'}, 
    {'function': ('android.content.ContentResolver', 'update', {'0': 'content://sms'}), 
        'name': u'更改短信'}, 
    {'function': ('android.content.ContentResolver', 'insert', {'0': 'content://sms'}), 
        'name': u'短信插入'}, 
    {'function': ('android.content.ContentResolver', 'query', {'0': 'content://sms'}), 
        'name': u'查看短信'}, 
    {'function': ('android.content.ContentResolver', 'query', {'0': 'content://icc/adn'}), 
        'name': u'查看通讯录'}, 
    {'function': ('android.content.ContentResolver', 'delete', {'0': 'content://sms'}), 
        'name': u'删除短信'}, 
    {'function': ('android.content.ContentResolver', 'delete', {'0': 'content://icc/adn'}), 
        'name': u'删除通讯录'}, 
]

def add_java_package_name(java_package_names, name):
    try:
        name = name[:name.rindex('.')]
        if name:
            java_package_names.add(name)
    except ValueError as err:
        pass
    return java_package_names

def set_java_package_names(app_info):
    java_package_names = set()
    java_package_names.add(app_info['packagename'])
    java_package_names = add_java_package_name(java_package_names, app_info['application_name'])
    for service in app_info['services']:
        java_package_names = add_java_package_name(java_package_names, service)
    for activity in app_info['activities']:
        java_package_names = add_java_package_name(java_package_names, activity)
    for receiver in app_info['receivers']:
        java_package_names = add_java_package_name(java_package_names, receiver)
    for provider in app_info['providers']:
        java_package_names = add_java_package_name(java_package_names, provider)
    app_info['java_package_names'] = java_package_names
    return app_info

def load_x_file(x_file_name, package_name):
    globals = {
        'false': False, 
        'true': True, 
        'null': None, 
    }
    with open(x_file_name) as x_file:
        x_lines = x_file.readlines()
    data = []
    droidmon_prefix = 'Droidmon-apimonitor-'
    for x_line in x_lines:
        if x_line.startswith(droidmon_prefix + package_name):
            #value_dict = eval(x_line[len(droidmon_prefix + package_name) + 1:], globals)
            json_line = x_line[len(droidmon_prefix + package_name) + 1:]
            try:
                value_dict = json.loads(json_line)
            except ValueError as err:
                #print 'json_line:', json_line
                continue
            data.append(value_dict)
    return data

def init_hook_datas(hook_datas, package_name):
    for i, hook_data in enumerate(hook_datas['hookConfigs']):
        hook_datas['hookConfigs'][i][package_name] = []
    return hook_datas

def add_api_position(x_data, java_package_names):
    try:
        exception_lines = x_data['exception'].strip().split('\n\tat ')
    except KeyError as err:
        print u'提醒：当前模拟器中的 Droidmon 非订制，不支持定位代码功能'
        x_data['exception_positions'] = []
        return x_data
    useful_exceptions = []
    for exception_line in exception_lines:
        for java_package_name in java_package_names:
            if exception_line.startswith(java_package_name):
                useful_exceptions.append(exception_line)
                break
    x_data['exception_positions'] = useful_exceptions
    return x_data

def make_hooks_datas(x_datas, package_name, java_package_names):
    with open(FILE_HOOKS_JSON) as hook_file:
        hook_datas = json.load(hook_file)
    hook_datas = init_hook_datas(hook_datas, package_name)
    for i, hook_data in enumerate(hook_datas['hookConfigs']):
        for x_data in x_datas:
            if x_data['class'] == hook_data['class_name'] and x_data['method'] == hook_data['method']:
                x_data = add_api_position(x_data, java_package_names)
                hook_datas['hookConfigs'][i][package_name].append(x_data)
    return hook_datas

def count_function(hook_datas, package_name):
    function_list = []
    for hook_data in hook_datas['hookConfigs']:
        if hook_data[package_name]:
            exception_positions = set()
            for single_call in hook_data[package_name]:
                exception_positions = exception_positions | set(single_call['exception_positions'])
            function_list.append({'class': hook_data['class_name'], 
                'method': hook_data['method'], 'exception_positions': list(exception_positions), 'call_list': hook_data[package_name]})
    return function_list

def exist_sen_func_full_match(class_func, function_real_list):
    api_positions = set()
    for function_real in function_real_list:
        if class_func[0] == function_real['class'] and class_func[1] == function_real['method']:
            if len(class_func) == 2:# 无参数的情况
                api_positions = add_api_position_single_api(api_positions, function_real['exception_positions'])
            else:
                match_args = class_func[2]
                for single_call in function_real['call_list']:
                    args_real = single_call['args']
                    flag = True
                    for match_positon in match_args.keys():
                        try:
                            if args_real[int(match_positon)] != match_args.get(match_positon):
                                flag = False
                                break
                        except IndexError as err:
                            flag = False
                            break
                    if flag:
                        api_positions = add_api_position_single_api(api_positions, single_call['exception_positions'])
    return list(api_positions)

def exist_sen_func_uri_contain(class_func, function_real_list):
    api_positions = set()
    for function_real in function_real_list:
        if class_func[0] == function_real['class'] and class_func[1] == function_real['method']:
            match_args = class_func[2]
            for single_call in function_real['call_list']:
                args_real = single_call['args']
                flag = True
                for match_positon in match_args.keys():
                    if match_args.get(match_positon) not in args_real[int(match_positon)]['uriString']:
                        flag = False
                        break
                if flag:
                    api_positions = add_api_position_single_api(api_positions, single_call['exception_positions'])
    return list(api_positions)

def make_sen_data(function_real_list):
    sensitives = []
    for func_to_sen in FUNCTION_TO_SENSITIVE_BEHAVIOR_RULES_FULL_MATCH:
        flag = True
        function_list_apis = []
        for func_rule in func_to_sen['function_list']:
            api_positions = exist_sen_func_full_match(func_rule, function_real_list)
            if not api_positions:
                flag = False
                break
            function_list_apis.append({'api': func_rule, 'api_positions': api_positions})
        if flag:
            sensitives.append({func_to_sen['name']: function_list_apis})
    for func_to_sen in FUNCTION_TO_SENSITIVE_BEHAVIOR_RULES_URI_CONTAIN:
        function_list_apis = []
        api_positions = exist_sen_func_uri_contain(func_to_sen['function'], function_real_list)
        if api_positions:
            function_list_apis.append({'api': func_to_sen['function'], 'api_positions': api_positions})
            sensitives.append({func_to_sen['name']: function_list_apis})
    return sensitives

def transfer_func_to_sen(function_real_list):
    sensitives_dict = {}
    
    sensitives_list = make_sen_data(function_real_list)
    for sensitives in sensitives_list:
        all_api_positions = []
        for single_api_positions in sensitives.values()[0]:
            all_api_positions.extend(single_api_positions['api_positions'])
        sensitives_dict[sensitives.keys()[0]] = all_api_positions
    return sensitives_dict

def save_file(file_name, data):
    with open(file_name, 'w') as file:
        file.write(json.dumps(data, indent=4, ensure_ascii=False))
    return

def analysis_x_logcat(x_file_name, app_info):
    package_name = app_info['packagename']
    
    # 新的 app_info 包含所有可能的manifest文件中提到的java代码所在的包名
    app_info = set_java_package_names(app_info)
    
    # func_timeflow 表示以时间顺序记录的函数调用列表。 TODO: 供后续制定以时间序列调用api的规则，进而检测分析。
    func_timeflow = load_x_file(x_file_name, package_name)
    save_file(x_file_name + '_timeflow_list.json', func_timeflow)
    
    # hook_datas 表示数据处理过程中的中间结果。
    hook_datas = make_hooks_datas(func_timeflow, package_name, app_info['java_package_names'])
    #save_file(x_file_name + '_hook_result.json', hook_datas)
    
    # func_statistic 表示以api为关键字的函数调用列表。 TODO: 供后续制定以api调用详细信息的规则，进而检测分析。
    func_statistic = count_function(hook_datas, package_name)
    save_file(x_file_name + '_count_function.json', func_statistic)
    
    # 根据 api调用->敏感行为 规则，查出其具有的敏感行为列表。
    sensitives = transfer_func_to_sen(func_statistic)
    save_file(x_file_name + '_sensitives.json', sensitives)
    
    # 根据 api调用->漏洞 规则，查出其具有的漏洞列表。
    vulnerabilities = transfer_func_to_vul(func_statistic, app_info)
    save_file(x_file_name + '_vulnerabilities.json', vulnerabilities)

    result = {'sensitives': sensitives, 'vulnerabilities': vulnerabilities}
    return result

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
