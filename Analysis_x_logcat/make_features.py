# -*- coding:UTF-8 -*-

import json
import numpy


def count_features(features):
    return (len(features['s1']) + len(features['s2']) + len(features['s3']) + 
            len(features['s4']) + len(features['s5']))


def get_s1_features(timeflows, droidmon_types):
    result = []
    for droidmon_type in droidmon_types:
        is_find = False
        for timeflow in timeflows:
            if timeflow['type'] == droidmon_type:
                is_find = True
                break
        if is_find:
            result.append(1)
        else:
            result.append(0)
    return result

def get_s2_features(timeflows, class_names):
    result = []
    for class_name in class_names:
        is_find = False
        for timeflow in timeflows:
            if timeflow['class'] == class_name:
                is_find = True
                break
        if is_find:
            result.append(1)
        else:
            result.append(0)
    return result

def get_s3_features(timeflows, class_methods):
    result = []
    for class_method in class_methods:
        is_find = False
        for timeflow in timeflows:
            if timeflow['class'] == class_method[0] and timeflow['method'] == class_method[1]:
                is_find = True
                break
        if is_find:
            result.append(1)
        else:
            result.append(0)
    return result

def get_s4_features(timeflows, class_method_args_matches):
    result = []
    for class_method_args_match in class_method_args_matches:
        is_find = False
        for timeflow in timeflows:
            if (timeflow['class'] == class_method_args_match[0] and 
                timeflow['method'] == class_method_args_match[1]):
                args_match = class_method_args_match[2]
                flag = True
                for (args_position, args_value) in args_match.items():
                    try:
                        if timeflow['args'][int(args_position)] != args_value:
                            flag = False
                            break
                    except IndexError as err:
                        flag = False
                        break
                if flag:
                    is_find = True
                    break
        if is_find:
            result.append(1)
        else:
            result.append(0)
    return result

def get_s5_features(timeflows, class_method_args_contains):
    result = []
    for class_method_args_contain in class_method_args_contains:
        is_find = False
        for timeflow in timeflows:
            if (timeflow['class'] == class_method_args_contain[0] and 
                timeflow['method'] == class_method_args_contain[1]):
                args_match = class_method_args_contain[2]
                flag = True
                for (args_position, args_value) in args_match.items():
                    try:
                        if args_value not in str(timeflow['args'][int(args_position)]):
                            flag = False
                            break
                    except IndexError as err:
                        flag = False
                        break
                if flag:
                    is_find = True
                    break
        if is_find:
            result.append(1)
        else:
            result.append(0)
    return result

def one_second_features(timeflows, features):
    result_list = []
    result_list.extend(get_s1_features(timeflows, features['s1']))
    result_list.extend(get_s2_features(timeflows, features['s2']))
    result_list.extend(get_s3_features(timeflows, features['s3']))
    result_list.extend(get_s4_features(timeflows, features['s4']))
    result_list.extend(get_s5_features(timeflows, features['s5']))
    return result_list

def fill_features(timeflows, features):
    result_list = []
    
    # 日志记录开始时间戳，单位毫秒（ms）
    start_timestamp = timeflows[0]['timestamp']
    
    end_timestamp = start_timestamp + 1000
    last_i = 0
    for i, timeflow in enumerate(timeflows):
        if timeflow['timestamp'] >= end_timestamp:
            result = one_second_features(timeflows[last_i:i], features)
            result_list.append(result)
            last_i = i
            end_timestamp = end_timestamp + 1000
    result = one_second_features(timeflows[last_i:], features)
    result_list.append(result)
    
    return result_list

def save_file(file_name, data):
    with open(file_name, 'w') as file:
        file.write(json.dumps(data, indent=4, ensure_ascii=False))
    return

def timeflow_to_numpy(timeflow_filename, feature_filename):
    with open(timeflow_filename) as fp:
        timeflows = json.load(fp)
    # 当时间序列为空时，则表示未提取到该 apk 运行时的任何特征，抛弃该 apk ，不生成 numpy 文件。
    if not timeflows:
        return
    with open(feature_filename) as fp:
        features = json.load(fp)
    
    # 获取特征个数
    features_nums = count_features(features)
    
    # 获取特征二维列表并保存，行*列，行为秒数，列为特征数，因此行不固定，列固定。
    features_list = fill_features(timeflows, features)
    save_file(timeflow_filename + '.view', features_list)
    
    # 数据转化并保存
    features_numpy = numpy.array(features_list)
    numpy.save(timeflow_filename + '.npy', features_numpy)
    
    return

def test():
    timeflow_filename = raw_input('请输入 timeflow 文件的绝对路径：')
    feature_filename = raw_input('请输入特征配置文件 s 的绝对路径：')
    timeflow_filename = timeflow_filename.strip().replace('\\', '')
    feature_filename = feature_filename.strip().replace('\\', '')
    
    timeflow_to_numpy(timeflow_filename, feature_filename)
    
    return

if __name__ == '__main__':
    print('Hello 戴鹏飞!!!')
    test()

