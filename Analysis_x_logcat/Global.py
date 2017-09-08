# coding: utf-8

import sys
reload(sys)
sys.setdefaultencoding('utf8')


def add_api_position_single_api(api_positions, exception_positions):
    if exception_positions:
        for exception_position in exception_positions:
            api_positions.add(exception_position)
    else:
        pass
        #api_positions.add('')
    return api_positions