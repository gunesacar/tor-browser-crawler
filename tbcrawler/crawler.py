from os import rename
from os.path import join, split
from pprint import pformat
from time import sleep

from selenium.common.exceptions import TimeoutException, WebDriverException

import common as cm
import utils as ut
from dumputils import Sniffer
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
        for self.job.batch in xrange(self.job.batches):
            wl_log.info("**** Starting batch %s ***" % self.job.batch)
            self.__do_batch()
            sleep(float(self.job.config['pause_between_batches']))

    def post_visit(self):
        pass

    def __do_batch(self):
        """
        Must init/restart the Tor process to have a different circuit.
        If the controller is configured to not pollute the profile, each
        restart forces to switch the entry guard.
        """
        with self.controller.launch():
            for self.job.site in xrange(len(self.job.urls)):
                if len(self.job.url) > cm.MAX_FNAME_LENGTH:
                    wl_log.warning("URL is too long: %s" % self.job.url)
                    continue

                self.__do_instance()
                sleep(float(self.job.config['pause_between_sites']))

    def __do_instance(self):
        for self.job.visit in xrange(self.job.visits):
            ut.create_dir(self.job.path)
            wl_log.info("*** Visit #%s to %s ***",
                        self.job.visit, self.job.url)
            with self.driver.launch():
                self.set_page_load_timeout()

                self.__do_visit()

                self.get_screenshot_if_enabled()
                self.post_visit()

    def __do_visit(self):
        with Sniffer(device=self.device,
                     path=self.job.pcap_file, filter=cm.DEFAULT_FILTER):
            sleep(1)  # make sure dumpcap is running
            try:
                with ut.timeout(cm.HARD_VISIT_TIMEOUT):
                    self.driver.get(self.job.url)

                    page_source = self.driver.page_source.strip().lower()
                    if ut.has_captcha(page_source):
                        wl_log.warning('captcha found')
                        self.job.add_captcha()

                    sleep(float(self.job.config['pause_in_site']))
            except (cm.HardTimeoutException, TimeoutException):
                wl_log.error("Visit to %s has timed out!", self.job.url)
            except ValueError as e:
                raise e
            except Exception as exc:
                wl_log.error("Unknown exception: %s", exc)

    def set_page_load_timeout(self):
        try:
            self.driver.set_page_load_timeout(
                cm.SOFT_VISIT_TIMEOUT)
        except WebDriverException as seto_exc:
            wl_log.error("Setting soft timeout %s", seto_exc)

    def get_screenshot_if_enabled(self):
        if self.screenshots:
            try:
                self.driver.get_screenshot_as_file(self.job.png_file)
            except WebDriverException:
                wl_log.error("Cannot get screenshot.")


class CrawlerWebFP(CrawlerBase):
    def post_visit(self):
        sleep(float(self.job.config['pause_between_visits']))
        self.filter_packets_without_guard_ip()

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
    def post_visit(self):
        sleep(float(self.job.config['pause_between_visits']))
        self.filter_packets_without_guard_ip()


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
        attributes = [self.batch, self.site, self.instance]
        if self.captchas[self.global_visit]:
            attributes.insert(0, 'captcha')
        return join(cm.CRAWL_DIR, "_".join(map(str, attributes)))

    def __repr__(self):
        return "Batches: %s, Sites: %s, Visits: %s" \
               % (self.batches, len(self.urls), self.visits)
