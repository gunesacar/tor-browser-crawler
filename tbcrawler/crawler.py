from os import rename
from os.path import join
from pprint import pformat
from time import sleep
import stem
import random

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
            with self.controller.launch():
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
        for self.job.site in xrange(len(self.job.urls)):
            if len(self.job.url) > cm.MAX_FNAME_LENGTH:
                wl_log.warning("URL is too long: %s" % self.job.url)
                continue

            self.__do_visits()
            sleep(float(self.job.config['pause_between_sites']))

    def __do_visits(self):
        for self.job.visit in xrange(self.job.visits):
            wl_log.info("*** Visit #%s to %s ***", self.job.visit, self.job.url)
            try:
                ut.create_dir(self.job.path)
                with self.driver.launch():
                    self.set_page_load_timeout()

                    self.__do_instance()

                    self.get_screenshot_if_enabled()
                    self.post_visit()
            except (cm.HardTimeoutException, TimeoutException):
                wl_log.error("Visit to %s has timed out!", self.job.url)
            except ValueError as e:
                raise e
            except Exception as exc:
                wl_log.error("Unknown exception: %s", exc)

    def __do_instance(self):
        with Sniffer(device=self.device,
                     path=self.job.pcap_file, filter=cm.DEFAULT_FILTER):
            sleep(1)  # make sure dumpcap is running
            with ut.timeout(cm.HARD_VISIT_TIMEOUT):
                self.driver.get(self.job.url)
                page_source = self.driver.page_source.strip().lower()
                if ut.has_captcha(page_source):
                    wl_log.warning('captcha found')
                    self.job.add_captcha()
                sleep(float(self.job.config['pause_in_site']))

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
    def __do_batch(self):
        self.controller.set_conf('__LeaveStreamsUnattached', '1')  # leave stream management to us
        def attach_stream(stream):
            # at this point stem should have some circuits created alreay
            # TODO: have a fallback if not...
            circuits = self.controller.get_circuits(default=[])
            # TODO: do we want to check the purpose and status of the circuit?
            circ_sample = random.sample([c for c in circuits if len(c.path) == 3], 1)
            if stream.status == 'NEW':
                new_path = circ_sample.path
                new_path[1] = self._MIDDLE_FINGERPRINT
                circuit_id = self.controller.new_circuit(new_path, await_build = True)
                self.controller.attach_stream(stream.id, circuit_id)

        self.controller.add_event_listener(attach_stream, stem.control.EventType.STREAM)

        super(CrawlerWebFP, self).__init__()

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
