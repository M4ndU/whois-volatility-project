import volatility.commands as commands
import volatility.plugins.common as common
import volatility.scan as scan
import volatility.utils as utils
import volatility.addrspace as addrspace
import volatility.debug as debug
import volatility.obj as obj
import binascii
import csv
import json

class kakaoScanner(scan.BaseScanner):
    checks = [ ]

    def __init__(self, needles = None):
        self.needles = needles
        self.checks = [ ("MultiStringFinderCheck", {'needles':needles})]
        scan.BaseScanner.__init__(self)

    def scan(self, address_space, offset = 0, maxlen = None):
        for offset in scan.BaseScanner.scan(self, address_space, offset, maxlen):
            yield offset


class KakaoFriends(common.AbstractWindowsCommand):
    """ Scans for and parses kakaotalk friends """

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('fname', short_option = 'N',
                          help = "any friend name", type = 'str'
                          )

    def calculate(self):
        if not self._config.fname:
            debug.error("use -name input name")
        else :
            fname = self._config.fname

        address_space = utils.load_as(self._config, astype = 'physical')

        try:
            fname_utfdata = unicode(fname, "utf-16")

        except UnicodeEncodeError:
            print('error')
            return
        except UnicodeDecodeError:
            print('error')
            return


        #need fix

        scanner = kakaoScanner(needles = [fname_utfdata.encode('utf-16-le')])
        for offset in scanner.scan(address_space):
            kakao_buff = address_space.read(offset-7, 4500)

            if(kakao_buff[0] != "\x00"):
                continue


            new_offset = offset -10 -(ord(kakao_buff[5:6])*0xff+ord(kakao_buff[6:7])) * 40


            timeout = 0
            while True:
                if timeout == 5:
                    break
                kakao_buff = address_space.read(new_offset, 4500)


                f_offset = kakao_buff.find('\x00\x01\x00\x88')

                if f_offset == -1:
                    new_offset -= 30
                    timeout += 1
                    continue
                else:
                    break

            if f_offset == -1:
                continue



            fn_list = []
            for i in range(0,0xff):
                fn_offset = kakao_buff.find('\x00'+chr(i)+'\x00\x88')

                if fn_offset == -1:
                    continue

                fn_l_offset = kakao_buff[fn_offset:].find('\x00')

                fn_list.append((kakao_buff[fn_offset+4:fn_l_offset]).encode('utf-16-le'))

            print(fn_list)


    def render_text(self, outfd, data):
        print data



class KakaoProfile(common.AbstractWindowsCommand):
    """ Scans for and parses kakaotalk my profile """

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('NULLTIME', short_option = 'N', default = True,
                          help = "Don't print entries with null timestamps",
                          action = "store_false")

    def calculate(self):
        address_space = utils.load_as(self._config, astype = 'physical')

        scanner = kakaoScanner(needles = ['"emailAddress":"',
                                          ])

        for offset in scanner.scan(address_space):
            kakao_buff = address_space.read(offset, 4500)

            end_offset = kakao_buff.find('","uuidSearchable":')

            if end_offset == -1:
                continue

            if kakao_buff[end_offset+19: end_offset+19+5] == "true}":
                end_offset += 25
            elif kakao_buff[end_offset+19: end_offset+19+6] == "false}":
                end_offset += 26
            else:
                continue

            kakao_data ="{" + kakao_buff[:end_offset]
            kakao_utfdata = kakao_data.decode('utf-8')
            kakao_utfdata = kakao_utfdata.replace('\x00', '')
            json_data = json.loads(kakao_utfdata, encoding="utf-8")

            profile_tuple = (json_data["emailAddress"], json_data["serviceUserId"], json_data["formattedPstnNumber"], json_data["statusMessage"], json_data["nickName"], json_data["originalProfileImageUrl"],json_data["action"]["title"], json_data["server_time"], json_data["uuid"], json_data["uuidSearchable"])

            print(profile_tuple)

    def render_text(self, outfd, data):
        print data


class kakaoPat():

  def A_pat(self, kakao_buff):

    end_offset = kakao_buff.find('\x5B\x31\x32\x39\x36\x34\x5D')

    if end_offset == -1:
      return

    tmp = kakao_buff.find('\x2E\x63\x70\x70')
    if tmp != -1:
      return

    kakao_data = kakao_buff[7:end_offset]
    utfend_offset = kakao_data.find('\x00\x00')

    if utfend_offset == -1:
      return
    elif utfend_offset % 2 == 0:
      kakao_data = kakao_buff[:utfend_offset]
    elif utfend_offset % 2 != 0:
      kakao_data = kakao_buff[:utfend_offset] + '\x00'

    try:
      kakao_utfdata = unicode(kakao_data, 'utf-16')
      return kakao_utfdata
    except UnicodeEncodeError:
      return
    except UnicodeDecodeError:
      return

  def BC_pat(self, kakao_buff):

    end_offset = kakao_buff.find('\x65\x6C\x61\x70\x73\x65\x64\x3D\x30')

    if end_offset == -1:
      return
    else:
      kakao_buff = kakao_buff[7:end_offset]

    utfend_offset = kakao_buff.find('\x00\x00')

    if utfend_offset == -1:
      return
    elif utfend_offset % 2 == 0:
      kakao_data = kakao_buff[:utfend_offset]
    elif utfend_offset % 2 != 0:
      kakao_data = kakao_buff[:utfend_offset] + '\x00'

    try:
      kakao_utfdata = unicode(kakao_data, 'utf-16')
      return kakao_utfdata
    except UnicodeEncodeError:
      return
    except UnicodeDecodeError:
      return

  def D_pat(self, kakao_buff):

    end_offset = kakao_buff.find('\x4C\x69\x6E\x6B\x4D\x65\x74\x61\x20\x57\x48\x45\x52\x45\x20\x6C\x69\x6E\x6B\x49\x64\x3D')

    if end_offset == -1:
      return
    else:
      kakao_buff = kakao_buff[7:end_offset]

    utfend_offset = kakao_buff.find('\x00\x00')

    if utfend_offset == -1:
      return
    elif utfend_offset % 2 == 0:
      kakao_data = kakao_buff[:utfend_offset]
    elif utfend_offset % 2 != 0:
      kakao_data = kakao_buff[:utfend_offset] + '\x00'

    try:
      kakao_utfdata = unicode(kakao_data, 'utf-16')
      return kakao_utfdata
    except UnicodeEncodeError:
      return
    except UnicodeDecodeError:
      return

  def O_pat(self, kakao_buff):

    kakao_buff = kakao_buff[:33]
    kakao_utfdata = kakao_buff.encode('utf-8')

    return 'Open Chat : ' + kakao_utfdata

class kakaorooms(common.AbstractWindowsCommand):

  def __init__(self, config, *args, **kwargs):
    commands.Command.__init__(self, config, *args, **kwargs)
    config.add_option('NAME', short_option='n', default=None, help='option Test', action='store', type='str')

  def calculate(self):
    addr_space = utils.load_as(self._config, astype='physical')

    scanner = kakaoScanner(needles = [
      '\x00\x00\x00\x00\x2E\x63\x70',
      '\x00\x00\x00\x00\x72\x6F\x6D',
      '\x00\x00\x00\x00\x5F\x4D\x45',
      '\x00\x00\x00\x00\x73\x3A\x25',
      '\x68\x74\x74\x70\x73\x3A\x2F\x2F\x6F\x70\x65\x6E\x2E\x6B\x61\x6B\x61\x6F\x2E\x63\x6F\x6D\x2F\x6F\x2F'
    ])

    for offset in scanner.scan(addr_space):
      mat = kakaoPat()
      kakao_buff = addr_space.read(offset, 130)

      if kakao_buff[4:7] == '\x2E\x63\x70':
        kakao_utfdata = mat.A_pat(kakao_buff)
      elif kakao_buff[4:7] == '\x73\x3A\x25':
        kakao_utfdata = mat.D_pat(kakao_buff)
      elif kakao_buff[:4] == '\x68\x74\x74\x70':
        kakao_utfdata = mat.O_pat(kakao_buff)
      else:
        kakao_utfdata = mat.BC_pat(kakao_buff)

      if kakao_utfdata == None:
        continue

      try:
        print kakao_utfdata
        print '---------------------------------------------'
      except UnicodeEncodeError:
        continue
      except UnicodeDecodeError:
        continue

  def render_text(self, outfd, data):
      print data

class KakaoMessages(common.AbstractWindowsCommand):
    """ Scans for and parses kakaotalk Messages """

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('NULLTIME', short_option = 'N', default = True,
                          help = "Don't print entries with null timestamps",
                          action = "store_false")

    def calculate(self):
        address_space = utils.load_as(self._config, astype = 'physical')

        scanner = kakaoScanner(needles = ['\x0d\x08\x08\x08\x06\x08\x08\x01\x08\x0d\x08\x08',
                                          ])
        print '*** Message Extract Start ***\n'

        for offset in scanner.scan(address_space):
            kakao_buff = address_space.read(offset, 4500)

            footer = kakao_buff.encode('hex')[24:27]
            footer_index = kakao_buff.encode('hex').find(footer, 28) + 1
            footer_index = footer_index / 2

            msg = kakao_buff[12 + 20:footer_index]
            msg = unicode(msg, 'utf-8')
            try:
                print '-----------------------------------------------------------------------------------------------------'
                print msg
                print '-----------------------------------------------------------------------------------------------------'
            except Exception:
                continue
        print '*** Message Extract End ***'

        scanner = kakaoScanner(needles = ['http://dn-m.talk.kakao.com/talkm/',
                                          ])
        print '*** Image Extract Start ***\n'

        for offset in scanner.scan(address_space):
            kakao_buff = address_space.read(offset, 4500)

            footer_index = kakao_buff.find('\x00')

            msg = kakao_buff[:footer_index]
            if len(msg) > 100:
                continue
            try:
                print '-----------------------------------------------------------------------------------------------------'
                print msg
                print '-----------------------------------------------------------------------------------------------------'
            except Exception:
                continue
        print '*** Image Extract End ***'

        scanner = kakaoScanner(needles = ['http://dn-v.talk.kakao.com/',
                                          ])
        print '*** Video Extract Start ***\n'

        for offset in scanner.scan(address_space):
            kakao_buff = address_space.read(offset, 4500)

            footer_index = kakao_buff.find('.mp4')

            msg = kakao_buff[:footer_index]
            if len(msg) > 100:
                continue
            try:
                print '-----------------------------------------------------------------------------------------------------'
                print msg
                print '-----------------------------------------------------------------------------------------------------'
            except Exception:
                continue
        print '*** Video Extract End ***'

    def render_text(self, outfd, data):
        pass
