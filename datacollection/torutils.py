import os
from selenium import webdriver
from selenium.common.exceptions import WebDriverException
from selenium.webdriver import DesiredCapabilities
from selenium.webdriver import firefox
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary
import shutil
import socket
from stem.control import Controller
import stem.process
from stem.util import term
import sys
from httplib import CannotSendRequest
import common as cm
from log import wl_log
from utils import clone_dir_with_timestap
import utils as ut


class TorController(object):
    def __init__(self, torrc_dict, tbb_version, tor_log='/dev/null'):
        self.torrc_dict = torrc_dict
        self.controller = None
        self.tbb_version = tbb_version
        self.tmp_tor_data_dir = None
        self.tor_process = None
        self.log_file = tor_log

    def tor_log_handler(self, line):
        wl_log.info(term.format(line))

    def restart_tor(self):
        """Kill current Tor process and run a new one."""
        self.kill_tor_proc()
        self.launch_tor_service(self.log_file)

    def kill_tor_proc(self):
        """Kill Tor process."""
        if self.tor_process:
            wl_log.info("Killing tor process")
            self.tor_process.kill()
        if self.tmp_tor_data_dir and os.path.isdir(self.tmp_tor_data_dir):
            wl_log.info("Removing tmp tor data dir")
            shutil.rmtree(self.tmp_tor_data_dir)

    def launch_tor_service(self, logfile='/dev/null'):
        """Launch Tor service and return the process."""
        self.log_file = logfile
        self.tmp_tor_data_dir = ut.clone_dir_with_timestap(
            cm.get_tor_data_path(self.tbb_version))

        self.torrc_dict.update({'DataDirectory': self.tmp_tor_data_dir,
                                'Log': ['INFO file %s' % logfile]})

        wl_log.debug("Tor config: %s" % self.torrc_dict)
        try:
            self.tor_process = stem.process.launch_tor_with_config(
                config=self.torrc_dict,
                init_msg_handler=self.tor_log_handler,
                tor_cmd=cm.get_tor_bin_path(self.tbb_version),
                timeout=270
                )
            self.controller = Controller.from_port()
            self.controller.authenticate()
            return self.tor_process

        except stem.SocketError as exc:
            wl_log.critical("Unable to connect to tor on port %s: %s" %
                            (cm.SOCKS_PORT, exc))
            sys.exit(1)
        except:
            # most of the time this is due to another instance of
            # tor running on the system
            wl_log.critical("Error launching Tor", exc_info=True)
            sys.exit(1)

        wl_log.info("Tor running at port {0} & controller port {1}."
                    .format(cm.SOCKS_PORT, cm.CONTROLLER_PORT))
        return self.tor_process

    def close_all_streams(self):
        """Close all streams of a controller."""
        wl_log.debug("Closing all streams")
        try:
            ut.timeout(cm.STREAM_CLOSE_TIMEOUT)
            for stream in self.controller.get_streams():
                wl_log.debug("Closing stream %s %s %s " %
                             (stream.id, stream.purpose,
                              stream.target_address))
                self.controller.close_stream(stream.id)  # MISC reason
        except ut.TimeExceededError:
            wl_log.critical("Closing streams timed out!")
        except:
            wl_log.debug("Exception closing stream")


class TorBrowserDriver(webdriver.Firefox, firefox.webdriver.RemoteWebDriver):
    def __init__(self, tbb_binary_path=None, tbb_profile_dir=None,
                 tbb_logfile_path=None,
                 tbb_version=cm.TBB_DEFAULT_VERSION, page_url=""):
        self.is_running = False
        self.tbb_version = tbb_version
        self.export_lib_path()
        # Initialize Tor Browser's profile
        self.page_url = page_url
        self.profile = self.get_own_tbb_profile(tbb_version)
        # set homepage to a blank tab
        self.profile.set_preference('browser.startup.page', "0")
        self.profile.set_preference('browser.startup.homepage', 'about:newtab')

        # configure Firefox to use Tor SOCKS proxy
        self.profile.set_preference('network.proxy.type', 1)
        self.profile.set_preference('network.proxy.socks', '127.0.0.1')
        self.profile.set_preference('network.proxy.socks_port', cm.SOCKS_PORT)
        if cm.DISABLE_RANDOMIZEDPIPELINENING:
            self.profile.set_preference(
                'network.http.pipelining.max-optimistic-requests', 5000)
            self.profile.set_preference(
                'network.http.pipelining.maxrequests', 15000)
            self.profile.set_preference('network.http.pipelining', False)

        self.profile.set_preference(
            'extensions.torlauncher.prompt_at_startup',
            0)

        # Disable cache - Wang & Goldberg's setting
        self.profile.set_preference('network.http.use-cache', False)

        # http://www.w3.org/TR/webdriver/#page-load-strategies-1
        # wait for all frames to load and make sure there's no
        # outstanding http requests (except AJAX)
        # https://code.google.com/p/selenium/wiki/DesiredCapabilities
        self.profile.set_preference('webdriver.load.strategy', 'conservative')
        # Note that W3C doesn't mention "conservative", this may change in the
        # upcoming versions of the Firefox Webdriver
        # https://w3c.github.io/webdriver/webdriver-spec.html#the-page-load-strategy

        # prevent Tor Browser running it's own Tor process
        self.profile.set_preference('extensions.torlauncher.start_tor', False)
        self.profile.set_preference(
            'extensions.torbutton.versioncheck_enabled', False)
        self.profile.update_preferences()
        # Initialize Tor Browser's binary
        self.binary = self.get_tbb_binary(tbb_version=self.tbb_version,
                                          logfile=tbb_logfile_path)

        # Initialize capabilities
        self.capabilities = DesiredCapabilities.FIREFOX
        self.capabilities.update({'handlesAlerts': True,
                                  'databaseEnabled': True,
                                  'javascriptEnabled': True,
                                  'browserConnectionEnabled': True})

        try:
            super(TorBrowserDriver, self)\
                .__init__(firefox_profile=self.profile,
                          firefox_binary=self.binary,
                          capabilities=self.capabilities)
            self.is_running = True
        except WebDriverException as error:
            wl_log.error("WebDriverException while connecting to Webdriver %s"
                         % error)
        except socket.error as skterr:
            wl_log.error("Error connecting to Webdriver")
            wl_log.error(skterr.message)
        except Exception as e:
            wl_log.error("Error connecting to Webdriver: " + str(e))

    def export_lib_path(self):
        os.environ["LD_LIBRARY_PATH"] = os.path.dirname(
            cm.get_tor_bin_path(self.tbb_version))

    def get_tbb_binary(self, tbb_version, binary=None, logfile=None):
        """
        Returns a :class:`FirefoxBinary` pointing to the TBB's firefox binary.

        :Args:
        :param string binary: The path to the TBB's firefox binary.
        :param string logfile: The path to the file to store the firefox
                browser log messages and JS addons/extension messages in.

        """
        tbb_logfile = None
        if not binary:
            binary = cm.get_tb_bin_path(tbb_version)
        if logfile:
            tbb_logfile = open(logfile, 'a+')

        # in case you get an error for the unknown log_file, update selenium
        tbb_binary = FirefoxBinary(firefox_path=binary,
                                   log_file=tbb_logfile)
        return tbb_binary

    def get_own_tbb_profile(self, version):
        profile_directory = cm.get_tbb_profile_path(version)
        self.prof_dir_path = clone_dir_with_timestap(profile_directory)
        try:
            tbb_profile = webdriver.FirefoxProfile(self.prof_dir_path)
        except Exception:
            wl_log.error("Error creating the TB profile", exc_info=True)
        else:
            return tbb_profile

    def quit(self):
        """
        Overrides the base class method cleaning the timestamped profile.

        """
        self.is_running = False
        try:
            wl_log.info("Quit: Removing profile dir")
            shutil.rmtree(self.prof_dir_path)
            super(TorBrowserDriver, self).quit()
        except CannotSendRequest:
            wl_log.error("CannotSendRequest while quitting TorBrowserDriver",
                         exc_info=False)
            # following is copied from webdriver.firefox.webdriver.quit() which
            # was interrupted due to an unhandled CannotSendRequest exception.

            # kill the browser
            self.binary.kill()
            # remove the profile folder
            try:
                shutil.rmtree(self.profile.path)
                if self.profile.tempfolder is not None:
                    shutil.rmtree(self.profile.tempfolder)
            except Exception as e:
                print(str(e))
        except Exception:
            wl_log.error("Exception while quitting TorBrowserDriver",
                         exc_info=True)
