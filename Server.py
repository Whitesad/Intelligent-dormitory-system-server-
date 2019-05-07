import socket
import threading
import json
import datetime
import pymysql
import threadpool

class Sock():
    hsotName=''
    hostIp=''
    port=5000
    sqlPasswd='yang'

    __userQueue__=[]
    __mesQueue__=[]

    def __init__(self):
        self.hsotName=socket.gethostname()
        self.hostIp=socket.gethostbyname(self.hostName)
 
        self.__socketServer__=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        print('Socket '+self.hsotName+' create')
        self.__socketServer__.bind(self.hostIp,self.port)
        self.__socketServer__.listen(10)
        print('Socket '+self.hostIp+' new listening')
        
        self.self.SockSQL = pymysql.connect(host='127.0.0.1', user='root', password=self.sqlPasswd, db='socketsql', charset='utf8', port=3306)
        print('user root socketSQL 连接成功')
        
        self.__chatTheradPool__=threadpool.ThreadPool(25)

    def startServer(self):
        while True:
            con, addr = self.__socketServer__.accept()  # recieve connect,addr includes ip and port
            print('Connect ' + addr[0] + ':' + str(addr[1]) + " Try to Connect")
            self.__LoginReq__(con)

    def __Thread_Listen__(self,con):
        while True:
            try:
                dict_dict = self.__Receive__(con)
                if (dict_dict["type"] == "TEXT_MES"):
                    print('Receive:')
                    print(dict_dict)
            except:
                print('XX' + " Exists")
                return


    def __Register__(self,dict_dict):
        query = 'SELECT * FROM normaluser where username="%s"'
        result_dict = self.__SQL_QUERY__(query % dict_dict['username'])
        if (not result_dict):
            insert = 'INSERT INTO normaluser values ("%s","%s")'
            if (self.__SQL_INSERT__(insert % (dict_dict['username'], dict_dict['password']))):
                return 'AC'
            else:
                return 'REGISTER_ERROR'
        else:
            status = 'SAME_NAME'
        return status

    def __StartChatThread__(self,con):
        con.setblocking(0)
        self.__userQueue__.append(con)
        requests=threadpool.makeRequests(self.__Thread_Listen__,[con])
        for req in requests:
            self.__chatTheradPool__.putRequest(req)

    def __Check_Memship__(self,dict_dict):
        query = 'SELECT * FROM normaluser where username="%s"'
        result = ''
        result_dict = {}
        print('query:' + query % dict_dict['username'])
        try:
            result_dict = self.__SQL_QUERY__(query % dict_dict['username'])
            print('query result:')
            print(result_dict)
            if (not result_dict):
                result = 'NO_MEMSHIP'
            else:
                if (result_dict['password'] == dict_dict['password']):
                    result = 'AC'
                else:
                    result = 'WRONG_PASSWORD'
        except:
            result = 'QUERY_ERROR'
            print('QUERY_ERROR!')
        return result
    def __LoginReq__(self,con):
        dict_mes=self.__Receive__(con)
        if (dict_mes['type'] == 'LOGIN_MES'):
            if (dict_mes['status'] == 'login'):
                result = self.__Check_Memship__(dict_mes)
                if (result == 'AC'):
                    print('user ' + dict_mes['username'] + ' Login AC' + ' ip: ' + dict_mes['ip'])
                    self.__Send__(con, {'type': 'LOGIN_MES', 'status': 'AC'})

                elif (result == 'WRONG_PASSWORD'):
                    self.__Send__(con, {'type': 'LOGIN_MES', 'status': 'WRONG_PASSWORD'})
                elif (result == 'NO_MEMSHIP'):
                    self.__Send__(con, {'type': 'LOGIN_MES', 'status': 'NO_MEMSHIP'})
                elif (result == 'QUERY_ERROR'):
                    self.__Send__(con, {'type': 'LOGIN_MES', 'status': 'QUERY_ERROR'})
        elif (dict_mes['type'] == 'REGISTER_MES'):
            if (dict_mes['status'] == 'register'):
                result = self.__Register__(dict_mes)
                if (result == 'SAME_NAME'):
                    self.__Send__(con, {'type': 'REGISTER_MES', 'status': 'SAME_NAME'})
                elif (result == 'AC'):
                    self.__Send__(con, {'type': 'REGISTER_MES', 'status': 'AC'})
                elif (result == 'REGISTER_ERROR'):
                    self.__Send__(con, {'type': 'REGISTER_MES', 'status': 'REGISTER_ERROR'})
        try:
            dict_mes = self.__Receive__(con)
        except:
            return False

    def __Receive__(con):
        dict_bytes = con.recv(2048)
        dict_dict = json.loads(str(dict_bytes, encoding='utf8'))
        return dict_dict
    def __Send__(sock,dict):
        print(sock)
        bytes_mes=bytes(json.dumps(dict),encoding='utf8')
        sock.send(bytes_mes)
        print("send dict"+str(dict))

    def __SQL_INSERT__(self,string):
        cursor = self.SockSQL.cursor()
        status = False
        try:
            cursor.execute(string)
            self.SockSQL.commit()
            status = True
        except:
            self.SockSQL.rollback()
            status = False
        cursor.close()
        return status
    def __SQL_QUERY__(self,string):
        cursor = self.SockSQL.cursor(cursor=pymysql.cursors.DictCursor)
        cursor.execute(string)
        dict_list = cursor.fetchall()
        cursor.close()
        if (not dict_list):
            return {}
        else:
            return dict(dict_list[0])

    
def fun(string):
    print(string)


if __name__=="__main__":
    pool=threadpool.ThreadPool(10)
    requests = threadpool.makeRequests(fun,["whitesad"])
    for req in requests:
        pool.putRequest(req)
    pool.wait()
    threadpool.WorkRequest