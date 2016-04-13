from os.path import join
from pprint import pformat
from time import sleep

from selenium.common.exceptions import TimeoutException, WebDriverException

import common as cm
import utils as ut
from dumputils import Sniffer
from log import wl_log


class CrawlerBase(object):
    def __init__(self, driver, controller, screenshots=True):
        self.driver = driver
        self.controller = controller
        self.screenshots = screenshots

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
            wl_log.info("*** Visit #%s to %s ***", self.job.visit, self.job.url)
            with self.driver.launch():
                try:
                    self.driver.set_page_load_timeout(cm.SOFT_VISIT_TIMEOUT)
                except WebDriverException as seto_exc:
                    wl_log.error("Setting soft timeout %s", seto_exc)
                self.__do_visit()
                if self.screenshots:
                    try:
                        self.driver.get_screenshot_as_file(self.job.png_file)
                    except WebDriverException:
                        wl_log.error("Cannot get screenshot.")
                self.post_visit()
            sleep(float(self.job.config['pause_between_visits']))

    def __do_visit(self):
        with Sniffer(path=self.job.pcap_file, filter=cm.DEFAULT_FILTER):
            sleep(1)  # make sure dumpcap is running
            try:
                with ut.timeout(cm.HARD_VISIT_TIMEOUT):
                    self.driver.get(self.job.url)
                    sleep(float(self.job.config['pause_in_site']))
            except (ut.HardTimeoutException, TimeoutException):
                wl_log.error("Visit to %s has timed out!", self.job.url)
            except Exception as exc:
                wl_log.error("Unknown exception: %s", exc)


class CrawlerWebFP(CrawlerBase):
    def post_visit(self):
        guard_ips = set([ip for ip in self.controller.get_all_guard_ips()])
        wl_log.debug("Found %s guards in the consensus.", len(guard_ips))
        wl_log.info("Filtering packets without a guard IP.")
        try:
            ut.filter_pcap(self.job.pcap_file, guard_ips, strip=True)
        except Exception as e:
            wl_log.error("ERROR: filtering pcap file: %s.", e)
            wl_log.error("Check pcap: %s", self.job.pcap_file)


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
    def url(self):
        return self.urls[self.site]

    @property
    def path(self):
        attributes = [self.batch, self.site, self.instance]
        return join(cm.CRAWL_DIR, "_".join(map(str, attributes)))

    def __repr__(self):
        return "Batches: %s, Sites: %s, Visits: %s" \
               % (self.batches, len(self.urls), self.visits)


