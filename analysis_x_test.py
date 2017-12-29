# -*- coding: utf8 -*-

import os
os.environ.update({"DJANGO_SETTINGS_MODULE": "MobSF.settings"})
import shutil
import MobSF.settings as SETTINGS

import json
from mass_static_analysis import genMD5
from StaticAnalyzer.views.android.manifest_analysis import get_manifest
from StaticAnalyzer.views.android.manifest_analysis import manifest_data as get_manifest_data
from StaticAnalyzer.views.shared_func import Unzip
import traceback

from Analysis_x_logcat.analysis import analysis_x_logcat

BASE_DIR = '.'
UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')
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

def print_x_log_analysis_result(result):
    print u'\n检测到敏感行为：'
    print json.dumps(result['sensitives'], indent=4, ensure_ascii=False)
    
    print u'\n检测到漏洞：'
    print json.dumps(result['vulnerabilities'], indent=4, ensure_ascii=False)
    return

def main(apk_file_path, x_logcat_file_path):
    file_md5 = genMD5(apk_file_path)
    
    app_info = get_static_info(apk_file_path, file_md5)
    
    result = analysis_x_logcat(x_logcat_file_path, app_info)
    print_x_log_analysis_result(result)
    return

def test():
    print u'请输入apk文件的绝对路径：'
    apk_file_path = raw_input().strip()
    if apk_file_path.startswith('"') and apk_file_path.endswith('"'):
        apk_file_path = apk_file_path[1:-1]
    print 'apk_file_path:', apk_file_path
    print u'请输入x_logcat文件的绝对路径：'
    x_logcat_file_path = raw_input().strip()
    if x_logcat_file_path.startswith('"') and x_logcat_file_path.endswith('"'):
        x_logcat_file_path = x_logcat_file_path[1:-1]
    print 'x_logcat_file_path:', x_logcat_file_path
    main(apk_file_path, x_logcat_file_path)
    return

if __name__ == '__main__':
    try:
        test()
    except Exception as err:
        print traceback.format_exc()
