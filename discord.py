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

class DiscordScanner(scan.BaseScanner):
    checks = [ ]

    def __init__(self, needles = None):
        self.needles = needles
        self.checks = [ ("MultiStringFinderCheck", {'needles':needles})]
        scan.BaseScanner.__init__(self)

    def scan(self, address_space, offset = 0, maxlen = None):
        for offset in scan.BaseScanner.scan(self, address_space, offset, maxlen):
            yield offset


class DiscordProfile(common.AbstractWindowsCommand):
    """ Scans for and parses Discord my profile """

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

    def calculate(self):
        address_space = utils.load_as(self._config, astype = 'physical')

        scanner = DiscordScanner(needles = ['{"locale":"',
                                          ])

        for offset in scanner.scan(address_space):
            discord_buff = address_space.read(offset, 500)

            end_offset = discord_buff.find(',"contactSyncUpsellShown":')

            if end_offset == -1:
                continue


            if discord_buff[end_offset+26: end_offset+26+5] == "true}":
                end_offset += 32
            elif discord_buff[end_offset+26: end_offset+26+6] == "false}":
                end_offset += 33
            else:
                continue

            discord_data = discord_buff[:end_offset]
            discord_utfdata = discord_data.decode('utf-8')
            discord_utfdata = discord_utfdata.replace('\x00', '')
            json_data = json.loads(discord_utfdata, encoding="utf-8")
            print(json_data)

        scanner = DiscordScanner(needles = ['{"_state":{"users":[{"id":"',
                                          ])

        for offset in scanner.scan(address_space):
            discord_buff = address_space.read(offset, 4500)

            end_offset = discord_buff.find(',"_version":0}')

            if end_offset == -1:
                continue

            end_offset += 15

            discord_data = discord_buff[:end_offset]
            try:
                discord_utfdata = discord_data.decode('utf-8')
            except:
                continue
            discord_utfdata = discord_utfdata.replace('\x00', '')
            json_data = json.loads(discord_utfdata, encoding="utf-8")
            print(json_data)

    def render_text(self, outfd, data):
        print data
