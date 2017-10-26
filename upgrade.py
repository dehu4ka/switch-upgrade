from telnetlib import Telnet
import sys
import configparser
import socket
import re
import logging
from time import sleep



TIMEOUT = 1.0
handler = logging.StreamHandler()

LOGIN_PROMPTS = [
    re.compile(b'username: ', flags=re.I),
    re.compile(b'username:', flags=re.I),
    re.compile(b'login: ', flags=re.I),
    re.compile(b'login:', flags=re.I),
    re.compile(b'user name:', flags=re.I),
    re.compile(b'user name: ', flags=re.I),

]

PASSWORD_PROMPTS = [
    re.compile(b'pass: ', flags=re.I),
    re.compile(b'pass:', flags=re.I),
    re.compile(b'password: ', flags=re.I),
    re.compile(b'password:', flags=re.I),
]

AUTHENTICATION_FAILED = [
    re.compile(b'Authentication failed', flags=re.I),  # cisco
    re.compile(b'Password incorrect', flags=re.I),  # cisco
    re.compile(b'Login incorrect', flags=re.I),  # juniper
    re.compile(b'Bad Password', flags=re.I),  # zyxel
    re.compile(b'Error: Failed to authenticate', flags=re.I),  # huawei no tacacs
    re.compile(b'Error: Password incorrect', flags=re.I),  # huawei
    re.compile(b'Invalid user name and password', flags=re.I),  # SNR
]


class NoLoginPrompt(Exception):
    def __init__(self):
        Exception.__init__(self, "There was no _known_ login prompt!")


class NoPasswordPrompt(Exception):
    def __init__(self):
        Exception.__init__(self, "There was no _known_ login prompt!")


class NoKnownPassword(Exception):
    def __init__(self):
        Exception.__init__(self, "Trying to login with unknown password")


class NotLoggedIn(Exception):
    def __init__(self):
        Exception.__init__(self, "Trying to exec commands without logged in to device")


class BadCommandPrompt(Exception):
    def __init__(self):
        Exception.__init__(self, "Bad command/shell prompt discovered. Check timeouts and login credentials")


class NotConnected(Exception):
    def __init__(self):
        Exception.__init__(self, "Trying to do something on device without connection.")



def setup_logger(name, verbosity=1):
    """
    Basic logger
    """
    # formatter = logging.Formatter(fmt='%(asctime)s - %(levelname)s - %(module)s - %(message)s')
    # formatter = logging.Formatter(fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    formatter = logging.Formatter(fmt='%(message)s')  # looks very very better for telnet sessions
    handler.setFormatter(formatter)

    # Set up main logger
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    if verbosity > 1:
        logger.setLevel(logging.DEBUG)

    return logger


def a2b(ascii_str):  # ascii to binary
    return ascii_str.encode('ascii')


def b2a(bin_string):  # binary to ascii
    return bin_string.decode('ascii', 'replace')


class NE(object):
    def __init__(self, ip, username, passw):
        self.t = Telnet()
        self.timeout = TIMEOUT
        self.prompt = ''
        self.pager = self.init_pager()
        self.ip = ip
        self.l = setup_logger('net.equipment.generic', 2)  # 2 means debug
        self.username = username
        self.passw = passw
        self.is_connected = False

    @staticmethod
    def init_pager():
        #  Заполняем возможные значения пэйджеров, на выходе получается список. Будет заполняться позднее, исходя из
        #  того что выдаст зоопарка оборудования
        pagers = list()
        pagers.append(re.compile(b'---\(more\)---'))
        pagers.append(re.compile(b'---\(more.+\)---'))
        pagers.append(re.compile(b' --More-- '))
        pagers.append(re.compile(b'  ---- More ----'))
        # pagers.append(re.compile(b'return user view with Ctrl\+Z'))
        return pagers

    def connect(self):
        try:
            self.t.open(ip, 23, self.timeout)
        except ConnectionRefusedError:
            self.l.warning("Connection to %s is refused!", self.ip)
            return False
        except socket.timeout:
            self.l.warning("Connection to %s - timeout!", self.ip)
            return False
        except OSError as err:
            self.l.info("OS Error, probably host have some firewall turned on, firewall is sending ICMP reject"
                        "and OS Error exception raised.")
            self.l.info(err)
            return False
        self.is_connected = True

    def expect(self, re_list):
        """
        Expecting to find some of RE's in input re_list.

        :param re_list: List of compiled Regular Expressions

        :return: Returns tuple, first el - was any RE found or not, second - output in
        """
        str = self.t.expect(re_list, self.timeout)
        if str[0] == -1:
            self.l.debug("can't find expected string in string")
            # line below has very ugly output, so I have to comment it =)
            # self.l.debug("search was: %s", re_list)
            return False, b2a(str[2])  # not found
        self._print_recv(b2a(str[2]))
        # otherwise string is found, returning it ascii
        self.l.debug("Match object is %s" % str[1])  # prints match object for debugging purposes
        return True, b2a(str[2])
        # return str[2]

    def _print_recv(self, input_string):
        """
        Prints received output to console with colors

        :param input_string: The string will be colored in debug output

        :return: None
        """
        # We are going to print that, so...
        if input_string is True:
            input_string = 'True'
        if input_string is False:
            input_string = 'False'
        self.l.debug('<<<< received')
        self.l.debug(input_string)
        self.l.debug('<<<< received end')

    def send(self, line):
        """
        Sends string with ENTER key and do some fancy debug output
        :param line: string to send to device
        :return: None
        """
        self.l.debug('>>>> sending')
        self.l.debug(line)
        self.t.write(a2b(line + "\n"))
        self.l.debug('>>>> sending end')

    def _sleep(self, timeout=1.0):
        self.l.debug("Sleeping for " + str(timeout) + " sec")
        sleep(timeout)

    def _discover_prompt(self):
        """
        Discovers command prompt. Or configure prompt. Send Enter <CR> and waits wor result

        :return:
        """
        if not self.is_connected:
            raise NotConnected
        self.send('')  # sending empty command
        out = self.t.read_until(b'whatever?', self.timeout)  # wainting for io_timeout for command promt
        out = out.replace(b'\x1b[K', b'')
        """
        Thx to https://jcastellssala.com/2012/07/20/python-command-line-waiting-feedback-and-some-background-on-why/
        \r Escape sequence for a Carriage Return (Go to the beginning of the line).
        \x1b[ Code for CSI (Control Sequence Introducer, nothing to do with the TV-series. check Wikipedia). 
        It is formed by the hexadecimal escape value 1b (\x1b) followed by [.
        K is the Escape sequence code to Erase the line.
        """
        self._print_recv(b2a(out))  # reading it
        if out is not b"":
            self.prompt = b2a(out).splitlines()[-1]  # getting it
        else:
            self.l.error("Command prompt cant be empty")
            raise BadCommandPrompt
        if re.search(r'(\*)+', self.prompt, re.MULTILINE):
            # We have found * (asterisk character) in command prompt. Usually this is masked password.
            # So we cant handle it.
            self.l.error("We have found * (asterisk character) in command prompt. Usually this is masked password.")
            raise BadCommandPrompt
        self.l.debug("Discovered the prompt: " + self.prompt)
        self.is_logged = True
        return self.prompt

    def login(self):
        was_found, out = self.expect(LOGIN_PROMPTS)  # we need to wait for login prompt
        self._print_recv(out)  # debug out
        self.send(self.username)  # sending known username
        was_found, out = self.expect(PASSWORD_PROMPTS)  # waiting for password prompt
        self._print_recv(out)  # debug out
        self.send(self.passw)  # sending known password
        self._sleep(0.5)  # waiting for possible tacacs timeout
        try:
            self._discover_prompt()
        except BadCommandPrompt:
            return False
        return True

    def exec_cmd(self, cmd):
        """
        Executes command with ENTER key, returns command output
        :param cmd:
        :return:
        """
        output = ''  # all output in ascii will be here
        self.l.debug('>>>> sending')
        self.l.debug(cmd)
        self.t.write(a2b(cmd + "\n"))
        self.l.debug('>>>> sending end')
        expect_list = self.pager
        re_with_prompt = re.compile(a2b(self.prompt))
        expect_list.append(re_with_prompt)  # If we have in our expect list both shell prompt and more prompt,
        #  we should not wait too long
        while True:
            out = self.t.expect(self.pager, self.timeout)
            output += b2a(out[2])
            if out[0] == -1:
                break
            x = re.compile(a2b(self.prompt))
            if out[1].re != x:
                self.t.write(a2b(' '))  # sending SPACE to get next page
        return output

    @staticmethod
    def _multiline_search(search, where):
        """
        Performs multiline register-independent search and returns found value or False

        :param search: regexp to search with capture group (!) in it

        :param where: string where to search

        :return: None if not found or match
        """
        result_match_object = re.search(search, where, re.M | re.I)
        if result_match_object:
            return result_match_object.groups()[0]  # first match

        return None

    def get_model(self):
        ver = self.exec_cmd('disp ver')
        self.l.debug(ver)

        if self._multiline_search(r'(S2309TP-EI)', ver):
            if self._multiline_search(r'(V100R006C05)', ver):
                self.l.info('Actual software, no upgrade is needed')
                return 'S2309TP-EI-new'
            self.l.info('Old software, upgrade is needed')
            return 'S2309TP-EI'
        elif self._multiline_search(r'(S2309TP-SI)', ver):
            return 'S2309TP-SI'

        ver = self.exec_cmd('show ver')
        self.l.debug(ver)
        if self._multiline_search(r'(SNR-S2985G-8T)', ver):
            # Checking version
            if self._multiline_search(r'(R0241.0136)', ver):
                self.l.info('Actual software, no upgrade is needed')
                return 'SNR-S2985G-8T-new'
            else:
                self.l.info('Old software, upgrade is needed')
                return 'SNR-S2985G-8T'

        return None

    def disconnect(self):
        self.is_connected = False  # pointless ?
        self.t.close()

    def update_snr_2985g_firmware(self, ftp_host, ftp_username, ftp_passw):
        self.l.info('Starting to upgrade')
        upgrade_cmd = 'copy ftp://' + ftp_username + ':' + ftp_passw + '@' + ftp_host + \
                      '/soft/snr2985g-0136.img nos.img'
        self.l.info('Using this command: %s' % upgrade_cmd)

        self.send(upgrade_cmd)
        success_factor = 0
        if self.expect([b'\[Y\/N\]', ]):
            self.send('y')
            self.timeout = 60
            if self.expect([b'Get Img file size success'], )[0]:
                self.l.info('firmware file is exists on FTP server - success!')
                success_factor += 1
            if self.expect([b'Transfer complete', ])[0]:
                self.l.info('Firmware was downloaded from FTP server')
                success_factor += 1
            if self.expect([b'Write ok', ])[0]:
                self.l.info('Firmware was successfully written to device flash memory')
                success_factor += 1

            if success_factor == 3:
                # when everything is allright.
                self.timeout = 3
                self.exec_cmd('')  # Empty command
                # write memory
                self.send('wr')
                if self.expect([b'\[Y\/N\]', ])[0]:
                    self.send('y')
                    if self.expect([b'successful', ]):
                        self.l.info('Write mem - success')
                    else:
                        self.l.error('Can not save current configuration! Please do it manually')
                        return False
                else:
                    self.l.error('Do not seeing save prompt. Aborting')
                    return False

                self.timeout = TIMEOUT
                self.l.info('Rebooting NE...')
                self.send('reload')
                if self.expect([b'\[Y\/N\]', ])[0]:
                    self.send('y')

                self._sleep(0.5)
                self.disconnect()
                return True
            else:
                self.l.error('Something was wrong, please try to manually update firmware')
                self.disconnect()
                return False

        else:
            self.l.error("Didn't see overwrite prompt, exiting")
            self.disconnect()
            return False

    def update_s2309ei_firmware(self, ftp_host, ftp_username, ftp_passw, sw_path, sw_image):
        self.l.info('Trying to update firmware on %s' % self.ip)
        dir_output = self.exec_cmd('dir')
        free_size = self._multiline_search(r'\((\d,\d+) KB free\)', dir_output)
        free_size = int(free_size.replace(',', ''))
        self.l.debug("Free size: %s" % free_size)
        if free_size < 7000:
            self.l.error('Not enough free disk size, please try to update firmware manually')
            return False

        # Sending 'ftp 10.205.x.x'
        self.send('ftp ' + ftp_host)
        if not self.expect([b'(User.+:)', ])[0]:
            self.l.error('Can not find ftp username prompt')
            return False

        # Sending username
        self.send(ftp_username)
        if not self.expect([b'(password:)', ])[0]:
            self.l.error('Can not find ftp password prompt')
            return False

        # Sending password
        self.send(ftp_passw)
        if not self.expect([b'(Login successful.)', ])[0]:
            self.l.error('FTP login was unsuccessful!')
            return False
        if not self.expect([b'(\[ftp\])', ])[0]:
            self.l.error('Can not get FTP prompt after login')
            return False

        # Changing directory
        self.send('cd ' + sw_path)
        if not self.expect([b'(Directory successfully changed.)', ])[0]:
            self.l.error('Can not change directory')
            return False
        if not self.expect([b'(\[ftp\])', ])[0]:
            self.l.error('Can not get FTP prompt after directory changing')
            return False

        # switching to binary mode. It may be pointless, but...
        self.send('bin')
        if not self.expect([b'(Switching to Binary mode.)', ])[0]:
            self.l.error('Can not switch to binary mode')
            return False
        if not self.expect([b'(\[ftp\])', ])[0]:
            self.l.error('Can not get FTP prompt after directory changing')
            return False

        # Getting firmware image to flash
        self.timeout = 300  # normally file transfer completed in 108 seconds
        self.send('get ' + sw_image)
        if not self.expect([b'(Transfer complete.)', ])[0]:
            self.l.error('Something was wrong, FTP transfer was not completed')
            return False
        if not self.expect([b'(\[ftp\])', ])[0]:
            self.l.error('Can not get FTP prompt after file transfer')
            return False
        # exiting from FTP mode
        self.timeout = 1.0
        self.send('quit')

        # Checking if new firmware exists on flash
        dir_output = self.exec_cmd('dir')
        self.l.debug('Dir output after FTP transfer')
        self.l.debug(dir_output)
        if not re.search(sw_image, dir_output, re.I | re.M):
            self.l.error('Can not find downloaded software on flash')
            return False

        # setting new startup firmware
        self.timeout = 30  # For BOOTROM upgrade
        self.send('startup system-software ' + sw_image)
        output = self.t.read_until(b'whatever?', self.timeout)
        if re.search(a2b('Continue?'), output, re.I | re.M):
            self.send('y')

        self.t.timeout = 1.0
        output = self.exec_cmd('disp startup')
        self.l.debug('disp startup output is:')
        self.l.debug(output)
        if not re.search(sw_image, output, re.I | re.M):
            self.l.error('Can not find new software in startup list')
            return False
        else:
            self.l.info('New firmware was found in startup list. WoW! Rebooting now!')

        # timeout for saving configuration
        self.t.timeout = 5
        self.send('save')
        if not self.expect([b'\[Y\/N\]', ])[0]:
            self.l.error('Can not find save prompt')
            return False
        self.send('y')
        if not self.expect([b'Save the configuration successfully.', ])[0]:
            self.l.error('Can not save configuration!')
            return False

        self.send('reboot')
        if not self.expect([b'\[Y\/N\]', ])[0]:
            self.l.error('Can not find reboot prompt')
            return False
        self.send('n')
        self._sleep(1)
        self.disconnect()





        return False


if __name__ == '__main__':
    ip = sys.argv[1]
    config = configparser.ConfigParser()
    config.read('config.ini')
    username = config['Auth']['username']
    passw = config['Auth']['passw']

    ftp_host = config['FTP']['host']
    ftp_username = config['FTP']['username']
    ftp_passw = config['FTP']['passw']
    print("Trying to upgrade NE with IP: %s, login: %s" % (ip, username))

    ip = '10.205.28.124'
    ne = NE(ip, username, passw)
    ne.connect()
    ne.login()
    vendor = ne.get_model()
    if vendor == 'SNR-S2985G-8T':
        if ne.update_snr_2985g_firmware(ftp_host, ftp_username, ftp_passw):
            exit(0)
        else:
            exit(1)

    if vendor == 'S2309TP-EI':
        sw_path = config['S2309TP-EI']['sw_path']
        sw_image = config['S2309TP-EI']['sw_image']
        if ne.update_s2309ei_firmware(ftp_host, ftp_username, ftp_passw, sw_path, sw_image):
            exit(0)
        else:
            exit(1)


    exit(0)
