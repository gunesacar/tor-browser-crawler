import os
import shutil
import ConfigParser
import unittest
from glob import glob
from os.path import isfile, isdir

from tbcrawler import common as cm, utils as ut
import netifaces
from tbcrawler.torcontroller import TorController
from tbcrawler.pytbcrawler import TorBrowserWrapper, setup_virtual_display, build_crawl_dirs
from tbselenium.common import USE_RUNNING_TOR
from tbcrawler import crawler as crawler_mod
from tbcrawler.crawler import CrawlerBase

TEST_URL_LIST = ['https://www.google.de',
                 'https://torproject.org',
                 'https://firstlook.org/theintercept/']


class CrawlerTest(unittest.TestCase):
    def setUp(self):
        cm.CONFIG_FILE = os.path.join(cm.TEST_DIR, 'config.ini')
        self.config = ConfigParser.RawConfigParser()
        self.config.read(cm.CONFIG_FILE)

    def configure_crawler(self, crawl_type, config_section):
        device = netifaces.gateways()['default'][netifaces.AF_INET][1]
        tbb_dir = os.path.abspath(cm.TBB_DIR)

        # Configure controller
        torrc_config = ut.get_dict_subconfig(self.config,
                                             config_section, "torrc")
        self.controller = TorController(tbb_dir,
                                        torrc_dict=torrc_config,
                                        pollute=False)

        # Configure browser
        ffprefs = ut.get_dict_subconfig(self.config,
                                        config_section, "ffpref")
        tbb_logfile_path = os.path.join(cm.LOGS_DIR, 'ff.log')
        socks_port = int(torrc_config['socksport'])
        self.driver = TorBrowserWrapper(tbb_dir,
                                        tbb_logfile_path=tbb_logfile_path,
                                        tor_cfg=USE_RUNNING_TOR,
                                        pref_dict=ffprefs,
                                        socks_port=socks_port,
                                        canvas_allowed_hosts=[])

        # Instantiate crawler
        crawl_type = getattr(crawler_mod, "Crawler" + crawl_type)
        screenshots = True
        self.crawler = crawl_type(self.driver, self.controller,
                                  device=device, screenshots=screenshots)

        # Configure job
        self.job_config = ut.get_dict_subconfig(self.config,
                                                config_section, "job")
        # Run display
        virtual_display = ''
        self.xvfb_display = setup_virtual_display(virtual_display)

    @unittest.skip("TODO. skip for now")
    def test_crawl(self):
        # this test takes at least a few minutes to finish
        crawler = CrawlerBase(cm.TORRC_WANG_AND_GOLDBERG, TEST_URL_LIST,
                              cm.TBB_DEFAULT_VERSION, capture_screen=True)
        try:
            crawler.crawl(1, 1)  # we can pass batch and instance numbers
        except Exception as e:
            self.fail("It raised an exception: %s" % e)
        self.assertTrue(isdir(crawler.crawl_dir))
        self.assertTrue(isdir(crawler.crawl_logs_dir))
        self.assertTrue(isfile(crawler.log_file))
        self.assertTrue(isfile(crawler.tor_log))
        self.assertEqual(crawler.experiment, cm.EXP_TYPE_WANG_AND_GOLDBERG)
        self.assertListEqual(crawler.urls, TEST_URL_LIST)
        self.assertEqual(crawler.tbb_version, cm.TBB_DEFAULT_VERSION)
        self.assertFalse(crawler.xvfb)
        crawler.stop_crawl(pack_results=True)
        tar_gz_crawl_data = crawler.crawl_dir + ".tar.gz"
        self.assertTrue(isfile(tar_gz_crawl_data))
        shutil.rmtree(crawler.crawl_dir)
        os.remove(tar_gz_crawl_data)

    def test_cloudflare_captcha_page(self):
        expected_pcaps = 2

        self.configure_crawler('WebFP', 'captcha_test')

        url = 'https://cloudflare.com/'
        job = crawler_mod.CrawlJob(self.job_config, [url])
        cm.CRAWL_DIR = os.path.join(cm.TEST_DIR,
                                    'test_cloudflare_captcha_results')
        build_crawl_dirs()
        os.chdir(cm.CRAWL_DIR)
        try:
            self.crawler.crawl(job)  # we can pass batch and instance numbers
        finally:
            self.driver.quit()
            self.controller.quit()

        capture_dirs = glob(os.path.join(cm.CRAWL_DIR, 'captcha_*'))
        self.assertEqual(expected_pcaps, len(capture_dirs))
        shutil.rmtree(cm.CRAWL_DIR)

    def test_not_captcha_after_captcha(self):
        self.configure_crawler('WebFP', 'captcha_test')

        known_captcha_url = 'https://cloudflare.com'
        known_not_captcha_url = 'https://check.torproject.org/'
        urls = [known_captcha_url, known_not_captcha_url]
        job = crawler_mod.CrawlJob(self.job_config, urls)
        cm.CRAWL_DIR = os.path.join(cm.TEST_DIR,
                                    'test_not_captcha_after_captcha')
        self.run_crawl(job)

        for _dir in os.listdir(cm.CRAWL_DIR):
            marked_captcha = _dir.startswith('captcha_')
            is_torproject_dir = '_1_' in _dir
            if is_torproject_dir:
                self.assertTrue(not marked_captcha)
            else:
                self.assertTrue(marked_captcha)

        shutil.rmtree(cm.CRAWL_DIR)

    def test_captcha_not_captcha_2_batches(self):
        self.configure_crawler('WebFP', 'test_captcha_not_captcha_2_batches')

        known_captcha_url = 'https://cloudflare.com'
        known_not_captcha_url = 'https://check.torproject.org/'
        urls = [known_captcha_url, known_not_captcha_url]
        job = crawler_mod.CrawlJob(self.job_config, urls)
        cm.CRAWL_DIR = os.path.join(cm.TEST_DIR,
                                    'test_not_captcha_after_captcha')
        self.run_crawl(job)

        for _dir in os.listdir(cm.CRAWL_DIR):
            marked_captcha = _dir.startswith('captcha_')
            is_torproject_dir = _dir.split('_')[-2] is '1'
            if is_torproject_dir:
                self.assertTrue(not marked_captcha)
            else:
                self.assertTrue(marked_captcha)

        shutil.rmtree(cm.CRAWL_DIR)

    def run_crawl(self, job):
        build_crawl_dirs()
        os.chdir(cm.CRAWL_DIR)
        try:
            self.crawler.crawl(job)  # we can pass batch and instance numbers
        finally:
            self.driver.quit()
            self.controller.quit()
if __name__ == "__main__":
    unittest.main()
