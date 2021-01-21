"""
smart_alarm
Copyright (c) 2020, Joaquin G. Duo

Code Licensed under LGPL License. See LICENSE file.
"""



def main():
    import os
    from smart_alarm.cmds_commands import tempature_report, ipcam_shot, ipcam_shot_cmd
    print(tempature_report())
    print(ipcam_shot('192.168.2.2','jardin_test.jpg',False))
    print(ipcam_shot_cmd(upload=True))


if __name__ == '__main__':
    main()
