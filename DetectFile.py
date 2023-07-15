import pkgutil
import re
import struct
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from initial import Ui_Dialog
#from PySide6 import QtWidgets
#from PyQt5 import uic, QtWidgets
#from PyQt5.QtWidgets import *
from pkgutil import extend_path

from PySide6.QtUiTools import QUiLoader
from PySide6.QtWidgets import QWidget, QMessageBox, QApplication, QTableWidget, QTableWidgetItem, QDialog, QFileDialog
from PySide6.QtGui import QAction, QIcon
from qt_material import apply_stylesheet
import json
#from work.view.tool import Tool

#form_class = uic.loadUiType("initial.ui")[0]

class DetectTool(QDialog, Ui_Dialog):
    #tool: Tool

    def __init__(self, parent = None, openAction=None):
        super(DetectTool, self).__init__(parent)
        #self.tool = Tool
        #self.addToolBar(self.tool)

        #self.ui = uic.loadUi("initial.ui", self)
        #self.ui.show()
        #self.app = QtWidgets.QApplication(sys.argv)
        #self.window = QWidget.QMainWindow()
        self.main = QUiLoader().load('initial.ui', self)
        self.setupUi(self)
        apply_stylesheet(self, 'light_red.xml')

        self.DetectCount = 0
        self.helpAction = QAction(QIcon(None), 'help', self)
        self.helpAction.triggered.connect(self.help_action_click)

        self.addAction(self.helpAction)
        #self.ui.setupUi(self)
        #self.create_menu()

        #self.initUI()
        self.pushButton_3.clicked.connect(self.pushButtonAnalyze)

        self.pushButton1.clicked.connect(self.openButtonClicked)


    def help_action_click(self):
        print("Tool")

    def get_dword(self, buf, off):
        return struct.unpack('<L', buf[off:off + 4])[0]

    def show_popup_ok(self, title: str, content: str):
        msg = QMessageBox()
        msg.setWindowTitle(title)
        msg.setText(content)
        msg.setStandardButtons(QMessageBox.Ok)
        #msg.setStyleSheet('font: 25 11pt "KoPubWorldDotum";background-color: rgb(255, 255, 255);')
        result = msg.exec()

    def pushButtonAnalyze(self):
        self.tableWidget.clearContents()
        try:
            self.detecting()

        except Exception as e:
            print(e)
            self.show_popup_ok(title="Warning", content="Select File")


    def detectOn(self):
        msg = QMessageBox()
        msg.setWindowTitle("Warning!")
        msg.setText("Detect Shredder Tool")
        msg.exec_()

    def initUI(self):
        #super().__init__()
        self.setWindowTitle('AIMed')
        #self.move(300,300)
       # self.setGeometry(200, 100, 400, 400)
        self.tableWidget = QTableWidget(self)
        self.tableWidget.setColumnWidth(1, 300)
        self.show()


    def openButtonClicked(self):

        fname = QFileDialog.getOpenFileName(self, 'Open File',dir='C:')
        self.filepath = str(fname[0])
        fileobject = self.filepath.split('/')
        file = fileobject[len(fileobject) - 1]
        self.fname = file
        self.label.setText(file)

    def detecting(self):

        fname = self.filepath
        fp = open(fname, 'rb')
        buf = fp.read()

        i = 0
        sector = 0
        diccnt = defaultdict(list)
        q = 0
        count = 0
        startrei = 0
        DetectCount = -1
        cnt = ''

        if buf[i:i + 4] == b'MLog':
            try:
                while (i >= 0):

                    if buf[i:i + 4] == b'MLog':
                        filename = ''
                        datetime1 = ''
                        self.voppattern = []
                        self.vfilename = []
                        self.vdatetime = []

                        count += 1
                        if count >= 1:
                            starti = i
                            startrei = starti + 0xb8

                        while (i >= 0):
                            n = buf[startrei:startrei + 8]
                            m = buf[startrei + 12: startrei + 20]  # startrei = 크기위치, startrai+12 = 38위치

                            if buf[startrei + 12] != 0x38:
                                if buf[startrei + 20] != 0x38:
                                    if buf[startrei + 28] == 0x38:
                                        startrei = startrei + 16
                                    else:
                                        starti = i + 4096
                                        if starti > 0:
                                            sector = int(int(starti + 201330688) / 512)
                                        i = starti
                                        break
                                else:
                                    startrei = startrei + 8

                            else:

                                jm = buf[startrei + 4: startrei + 8]

                                bytekeycnt = buf[startrei + 8: startrei + 12]
                                keycnt = int.from_bytes(bytekeycnt, "little")
                                bytekeyoffpos = buf[startrei + 12: startrei + 16]
                                keyoffpos = int.from_bytes(bytekeyoffpos, "little")
                                bytevalcnt = buf[startrei + 16: startrei + 20]
                                valcnt = int.from_bytes(bytevalcnt, "little")
                                bytevaloffpos = buf[startrei + 20: startrei + 24]
                                valoffpos = int.from_bytes(bytevaloffpos, "little")

                                virtualAllocator = buf[startrei + 24: startrei + 26]
                                LSNCheckpoint = buf[startrei + 32: startrei + 34]
                                hex_value = (virtualAllocator + LSNCheckpoint).hex()
                                cnt = int(hex_value.replace('-', ''), 16)


                                valoff = buf[startrei + valoffpos:startrei + valoffpos + 4]
                                bytevalsize = buf[startrei + valoffpos + 4:startrei + valoffpos + 8]
                                valsize = int.from_bytes(bytevalsize, "little")

                                for keyi in range(keycnt):
                                    # keyoff = buf[startrei + keyoffpos:startrei + keyoffpos + 4]

                                    # print(startrei)
                                    tmpkeyoff = (startrei + keyoffpos + (8 * keyi))
                                    bytekeyoff = buf[tmpkeyoff:tmpkeyoff + 4]
                                    bytekeysize = buf[tmpkeyoff + 4:tmpkeyoff + 8]
                                    keysize = int.from_bytes(bytekeysize, "little")

                                    keycontentpos = int.from_bytes(bytekeyoff, "little")
                                    keycontent = buf[startrei + keycontentpos:startrei + keycontentpos + keysize]
                                    # print(keyi, "번째 key값 : ", keycontent.hex())
                                    ah = keycontent.hex()

                                    # 파일명시그니처
                                    #fileexp =
                                    if '30010000c00100000000000030000100' in ah:
                                        filename = keycontent[16::2].decode('utf-8', 'ignore')
                                        print(filename)
                                        # print(filename.strip('00'))
                                        '''detected = chardet.detect(keycontent)
                                        decoded = keycontent.decode(detected["encoding"])
                                        print(decoded)'''
                                        # self.cnt = filename

                                    '''try:'''
                                    datemakeint = int.from_bytes(keycontent[8:16], "little")
                                    if datemakeint > 126120837550830000 and datemakeint < 157677573550830000:
                                        filedate = datemakeint.to_bytes(8, byteorder='big').hex()
                                        print('filedate', filedate)
                                        us = int(filedate, 16) / 10
                                        datetime1 = datetime(1601, 1, 1) + timedelta(microseconds=us)
                                        print('datetime', datetime1)
                                    '''except Exception as e:
                                        print(e)'''

                                for vali in range(valcnt):
                                    tmpvaloff = (startrei + valoffpos + (8 * vali))
                                    bytevaloff = buf[tmpvaloff:tmpvaloff + 4]
                                    valcontentpos = int.from_bytes(bytevaloff, "little")
                                    valcontent = buf[startrei + valcontentpos:startrei + valcontentpos + valsize]
                                    # print(vali, "번째 val값 : ", valcontent.hex())
                                    ah = valcontent.hex()
                                    if '30010000C0010000' in ah:
                                        filename = valcontent[16::2].decode('ascii', 'ignore') + ' [in Val]'
                                        print(filename)

                                    # try:
                                    datemakeint = int.from_bytes(valcontent[24:32], "little")
                                    if (datemakeint > 126120837550830000) and datemakeint < 157677573550830000:
                                        filedate = datemakeint.to_bytes(8, byteorder='big').hex()

                                        print('filedate', filedate)
                                        us = int(filedate, 16) / 10
                                        datetime1 = datetime(1601, 1, 1) + timedelta(microseconds=us)
                                        print('datetime', datetime1)


                                # arrop.append(hex(opcode[0]))
                                opInt = hex(jm[0])
                                opInt = opInt.replace('0x', '')
                                # a = int((opcode[0]),16)

                                diccnt[cnt] += [str(opInt), filename, datetime1]

                                startRecord = buf[startrei:startrei + 4]
                                size = self.get_dword(buf, startrei)
                                opHex = hex(jm[0])
                                print("opHex : ", opHex)
                                print(hex(virtualAllocator[0]), hex(virtualAllocator[1]), hex(LSNCheckpoint[0]),
                                      hex(LSNCheckpoint[1]))

                                finishi = startrei + size
                                startrei = finishi

                    else:
                        raise ValueError



            except Exception as e:
                print(e)

            # a=(','.join(diccnt.items()))
            # print('a', a)
            PatEasy = re.compile('44?25144471ff22f24')
            PatKernel = re.compile('6(1f){2}88825144471ff22f24')
            PatTurbo = re.compile('4444?2514444471ff2f24')
            Patx = re.compile('64444+251444(4+)74f22f24')
            PatHardwipe = re.compile('(1f4){2}71f4(251444){3}f22f24')
            PatHardwipe2 = re.compile('(1f4){2}71f4(251444){3}f22f24')
            PatFile = re.compile('441f471f4251444f22f24')
            PatPC = re.compile('444?25144471ff22f24')
            PatRemo = re.compile('41f4425144471ff22f24')
            PatSecure = re.compile('61f81f471f4(251444){9}f22f24')
            PatSuperFile = re.compile('46(1f1f8446){2}1f1f8441f471f4251444f22f24')
            PatWipeFile = re.compile('4471f4251444444f22f24')
            PatXTFile = re.compile('41f471f4251444f22f24')

            patt = [PatEasy, PatKernel, PatTurbo, Patx, PatHardwipe, PatFile, PatPC, PatRemo, PatSecure, PatSuperFile,
                    PatWipeFile, PatXTFile]


            #If Timevalue is different, Compare Name
            min_difference = float('inf')
            min_key = None
            keys_to_delete = []
            for key1 in sorted(diccnt.keys()):
                min_difference = float('inf')
                min_key = None

                for key in sorted(diccnt.keys()):
                    if key > key1:
                        difference = abs(key - key1)
                        if difference < min_difference:
                            min_difference = difference
                            min_key = key

                if min_key is not None:
                    if len(diccnt[key1]) >= 2 and len(diccnt[min_key]) >= 4:
                        if diccnt[key1][1::3][-1] == diccnt[min_key][1::3][1]:
                            diccnt[key1].extend(diccnt[min_key])
                            keys_to_delete.append(min_key)

                    new_entries = {}  # 새로운 항목을 저장할 딕셔너리 생성




            min_difference = float('inf')
            min_key = None
            keys_to_delete = []

            for key2 in sorted(diccnt.keys()):
                min_difference = float('inf')
                min_key = None
                for key22 in sorted(diccnt.keys()):
                    if key22 > key2:
                        difference = abs(key22 - key2)
                        if difference < min_difference:
                            min_difference = difference
                            min_key = key22

                if min_key is not None:
                    if len(diccnt[key2]) >= 1 and len(diccnt[min_key]) >= 1:
                        if diccnt[key2][1::3][-1] == diccnt[min_key][1::3][1]:
                            diccnt[key2].extend(diccnt[min_key])
                            keys_to_delete.append(min_key)



            for key in keys_to_delete:
                del diccnt[key]
            for k, v in diccnt.items():
                #         pattern,    Filename,   Time
                if 'Turbo_Gutmann' not in v[1::3][0]:
                    print(k, v[0::3], v[1::3], v[2::3], end='\n')
                self.k = k
                self.v = v
                self.voppattern = v[0::3]
                self.vfilename = v[1::3]
                self.vdatetime = v[2::3]

                c = self.vfilename
                b = self.vdatetime
                a = (''.join(self.voppattern))
                print(a)
                detectName = 'none detect'
                if re.match(Patx, a) or re.match(PatXTFile, a):
                    detectName = 'multi'
                if re.match(PatHardwipe, a):
                    detectName = 'Hardwipe'
                if re.match(PatTurbo, a):
                    detectName = 'TurboShredder'
                if re.match(PatKernel, a):
                    detectName = 'KernelShredder'
                if re.match(PatEasy, a):
                    detectName = 'EasyFileShredder'
                if re.match(PatRemo, a):
                    detectName = 'RemoFileShredder'
                if re.match(PatSecure, a):
                    detectName = 'Secure Eraser'
                if re.match(PatSuperFile, a):
                    detectName = 'Super File Shredder'
                if re.match(PatWipeFile, a):
                    detectName = 'Wipe File'


                strtime = ''

                try:
                    if detectName != 'none detect':
                        print('detect!!!')

                        settingname = detectName
                        # self.tableWidget1 = QTableWidget(self)

                    else:


                        settingname = '****'
                        if 'Turbo_Gutmann' not in self.vfilename[0]:
                            print('filename : ', self.vfilename, 'vdatetime: ', self.vdatetime)

                    self.DetectCount += 1
                    self.tableWidget.insertRow(self.DetectCount)

                    self.voppattern = str(self.voppattern)
                    self.voppattern = self.voppattern.replace("'", "")
                    self.voppattern = self.voppattern.replace(",", " -")

                    # setItem( col,row, value)

                    for ii in range(len(self.vfilename)):
                        if self.vfilename[ii] != '' and '\\x' not in self.vfilename[ii]:
                            strname1 = self.vfilename[ii]

                            break
                        else:
                            strname1 = 'no name'

                    for ii in range(len(self.vfilename)):
                        if self.vfilename[ii] != '' and self.vfilename[ii] != strname1:
                            strname2 = self.vfilename[ii]

                            break
                        else:
                            strname2 = 'no name'

                    if detectName == 'multi':
                        renamepattern = strname2

                        if re.match(r"^([a-z])\1+\.([A-Za-z])\1+" , renamepattern):
                            settingname = "xShredder"
                        elif re.match(r"[A-Za-z]+\.[A-Za-z]{3}$", renamepattern):
                            settingname = "XTFile"


                    self.tableWidget.setItem(self.DetectCount, 0, QTableWidgetItem(settingname))
                    self.tableWidget.setItem(self.DetectCount, 1, QTableWidgetItem(strname1))

                    self.tableWidget.setItem(self.DetectCount, 3, QTableWidgetItem(self.voppattern))

                    for jj in range(len(self.vdatetime)):
                        if self.vdatetime[jj] != '':
                            strtime = self.vdatetime[jj]
                        else:
                            strtime = 'no time'

                    self.tableWidget.setItem(self.DetectCount, 2, QTableWidgetItem(str(strtime)))

                    self.tableWidget.resizeColumnToContents(2)
                    self.tableWidget.resizeColumnToContents(3)
                except Exception as e:
                    print(e)

            if self.DetectCount > 0:
                self.detectOn()
        else :
            self.show_popup_ok('WARNING!', 'It is not Logfile')



if __name__ == '__main__':
    #app = QApplication(sys.argv)
    app = QApplication(sys.argv)

    ex = DetectTool()
    ex.show()
    app.exec()
