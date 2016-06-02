from os import rename, remove
from tempfile import gettempdir
from os.path import join, isfile
from pprint import pformat
from urlparse import urlsplit
from time import sleep
from shutil import move
import pickle
import stem
import random

from selenium.common.exceptions import TimeoutException, WebDriverException

import common as cm
import utils as ut
from dumputils import Sniffer, DumpcapTimeoutError
from log import wl_log


class CrawlerBase(object):
    def __init__(self, driver, controller, device='eth0', screenshots=True):
        self.driver = driver
        self.controller = controller
        self.screenshots = screenshots
        self.device = device

        self.job = None

    def crawl(self, job):
        """Crawls a set of urls in batches."""
        self.job = job
        wl_log.info("Starting new crawl")
        wl_log.info(pformat(self.job))
        while self.job.batch < self.job.batches:
            wl_log.info("**** Starting batch %s ***" % self.job.batch)
            with self.controller.launch():
                self.__do_batch()
            sleep(float(self.job.config['pause_between_batches']))
            self.job.batch += 1

    def post_visit(self):
        pass

    def cleanup_visit(self):
        pass

    def __do_batch(self):
        """
        Must init/restart the Tor process to have a different circuit.
        If the controller is configured to not pollute the profile, each
        restart forces to switch the entry guard.
        """
        while self.job.site < len(self.job.urls):
            if len(self.job.url) > cm.MAX_FNAME_LENGTH:
                wl_log.warning("URL is too long: %s" % self.job.url)
                continue

            self.__do_visits()
            sleep(float(self.job.config['pause_between_sites']))
            self.job.site += 1
        if self.job.site == len(self.job.urls):
            self.job.site = 0

    def __do_visits(self):
        while self.job.visit < self.job.visits:
            wl_log.info("*** Visit #%s to %s ***", self.job.visit, self.job.url)
	    try:
	        ut.create_dir(self.job.path)
	        self.save_checkpoint()
                with self.driver.launch():
                    self.set_page_load_timeout()
                    try:
                        self.__do_instance()
                        self.get_screenshot_if_enabled()
                    except (cm.HardTimeoutException, TimeoutException, DumpcapTimeoutError):
                        wl_log.error("Visit to %s has timed out!", self.job.url)
		    else:
		        self.post_visit()
                    finally:
                        self.cleanup_visit()
            except Exception as exc:
                wl_log.error("Unknown exception: %s" % repr(exc))
            self.job.visit += 1
        if self.job.visit == self.job.visits:
            self.job.visit = 0

    def __do_instance(self):
        with Sniffer(device=self.device,
                     path=self.job.pcap_file, filter=cm.DEFAULT_FILTER):
            sleep(1)  # make sure dumpcap is running
            with ut.timeout(cm.HARD_VISIT_TIMEOUT):
                self.driver.get(self.job.url)
                page_source = self.driver.page_source.encode('utf-8').strip().lower()
                with open(join(self.job.path, "source.html"), "w") as fhtml:
                    fhtml.write(page_source)
                if ut.has_captcha(page_source):
                    wl_log.warning('captcha found')
                    self.job.add_captcha()
                sleep(float(self.job.config['pause_in_site']))

    def save_checkpoint(self):
        fname = join(cm.CRAWL_DIR, "job.chkpt")
        if isfile(fname):
            remove(fname)
        with open(fname, "w") as f:
            pickle.dump(self.job, f)
        wl_log.info("New checkpoint at %s" % fname)

    def set_page_load_timeout(self):
        try:
            self.driver.set_page_load_timeout(
                cm.SOFT_VISIT_TIMEOUT)
        except WebDriverException as seto_exc:
            wl_log.error("Setting soft timeout %s", seto_exc)

    def get_screenshot_if_enabled(self):
        if self.screenshots:
            # selenium's bug: https://github.com/seleniumhq/selenium-google-code-issue-archive/issues/3596
            # set a timeout for getting a screenshot in case we hit the bug.
            try:
                with ut.timeout(5):
                    try:
                        self.driver.get_screenshot_as_file(self.job.png_file)
                    except WebDriverException:
                        wl_log.error("Cannot get screenshot.")
            except cm.HardTimeoutException:
                wl_log.error("Function to take the screenshot has timed out!")


class CrawlerWebFP(CrawlerBase):

    def cleanup_visit(self):
        addon_logfile = join(gettempdir(), 'tbb-http.log')
        if isfile(addon_logfile):
            remove(addon_logfile)

    def post_visit(self):
        sleep(float(self.job.config['pause_between_visits']))
        self.filter_packets_without_guard_ip()
        # move addon log to file
        addon_logfile = join(gettempdir(), 'tbb-http.log')
        if isfile(addon_logfile):
	    move(addon_logfile, join(self.job.path, 'tbb-http.log'))


    def filter_packets_without_guard_ip(self):
        guard_ips = set([ip for ip in self.controller.get_all_guard_ips()])
        wl_log.debug("Found %s guards in the consensus.", len(guard_ips))
        wl_log.info("Filtering packets without a guard IP.")
        try:
            ut.filter_pcap(self.job.pcap_file, guard_ips, strip=True)
        except Exception as e:
            wl_log.error("ERROR: filtering pcap file: %s.", e)
            wl_log.error("Check pcap: %s", self.job.pcap_file)


class CrawlerMiddle(CrawlerWebFP):

    def get_circuit_path():
        circ_id = self.controller.new_circuit(await_build=False)
        circ = self.controller.get_circuit(circ_id)
        path = circ.path
        self.controller.close_circuit(circ_id)
        return path

    def __do_batch(self):

        def attach_stream(stream):
            if stream.status == 'NEW':
                new_path = self.get_circuit_path()
                new_path[1] = self._MIDDLE_FINGERPRINT
                circ_id = self.controller.new_circuit(new_path, await_build=True)
                # TODO: do we want to check the purpose and status of the circuit?
                # await_build=True makes sure it's ready
                try:
                    wl_log.debug("Attach stream %s to circuit %s", stream.id, circ_id)
                    self.controller.attach_stream(stream.id, circuit_id)
                except stem.UnsatisfiableRequest as e:
                    wl_log.error("Attaching stream to custom circuit: %s", e)
                except stem.InvalidRequest as e1:
                    wl_log.error("Attaching stream to custom circuit: %s", e1)

        self.controller.controller.add_event_listener(attach_stream,
                                                      stem.control.EventType.STREAM)
        self.controller.controller.set_conf('__LeaveStreamsUnattached', '1')

        super(CrawlerWebFP, self).__do_batch()


class CrawlerMultitab(CrawlerWebFP):
    pass


class CrawlJob(object):
    def __init__(self, config, urls):
        self.urls = urls
        self.visits = int(config['visits'])
        self.batches = int(config['batches'])
        self.config = config

        # state
        self.site = 0
        self.visit = 0
        self.batch = 0
        self.captchas = [False] * (self.batches * len(self.urls) * self.visits)

    def add_captcha(self):
        try:
            captcha_filepath = ut.capture_dirpath_to_captcha(self.path)
            rename(self.path, captcha_filepath)

            self.captchas[self.global_visit] = True
        except OSError as e:
            wl_log.exception('%s could not be renamed to %s',
                             self.path, captcha_filepath)
            raise e

    @property
    def pcap_file(self):
        return join(self.path, "capture.pcap")

    @property
    def png_file(self):
        return join(self.path, "screenshot.png")

    @property
    def instance(self):
        return self.batch * self.visits + self.visit

    @property
    def global_visit(self):
        global_visit_no = self.site * self.visits + self.instance
        return global_visit_no

    @property
    def url(self):
        return self.urls[self.site]

    @property
    def path(self):
        website = urlsplit(self.url).hostname
        attributes = [self.batch, website, self.instance]
        if self.captchas[self.global_visit]:
            attributes.insert(0, 'captcha')

        return join(cm.CRAWL_DIR, "_".join(map(str, attributes)))

    def __repr__(self):
        return "Batches: %s/%s, Sites: %s/%s, Visits: %s/%s" \
            % (self.batch + 1, self.batches,
               self.site + 1, len(self.urls),
               self.visit + 1, self.visits)
