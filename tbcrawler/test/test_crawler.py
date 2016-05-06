import pytest
import os
import shutil
import ConfigParser
import unittest
from glob import glob
from os.path import isdir, join

from tbcrawler import common as cm, utils as ut
import netifaces
from tbcrawler.torcontroller import TorController
from tbcrawler.pytbcrawler import TorBrowserWrapper, setup_virtual_display, build_crawl_dirs
from tbselenium.common import USE_RUNNING_TOR
from tbcrawler import crawler as crawler_mod

TEST_URL_LIST = ['https://www.google.de',
                 'https://torproject.org',
                 'https://firstlook.org/theintercept/']
TEST_DIRS = join(cm.TEST_DIR, "dirs")


class CrawlerTest(unittest.TestCase):
    def setUp(self):
        # clean dirs
        if isdir(TEST_DIRS):
            shutil.rmtree(TEST_DIRS)
        os.mkdir(TEST_DIRS)

        cm.CONFIG_FILE = os.path.join(cm.TEST_FILES_DIR, 'config.ini')
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

    @pytest.mark.skipif(bool(os.getenv('CI', False)), reason='Skip in CI')
    def test_crawl(self):
        self.configure_crawler('Base', 'captcha_test')
        job = crawler_mod.CrawlJob(self.job_config, TEST_URL_LIST)
        cm.CRAWL_DIR = os.path.join(TEST_DIRS, 'test_crawl')
        self.run_crawl(job)
        # TODO: test for more conditions...
        self.assertGreater(len(os.listdir(cm.CRAWL_DIR)), 0)
        shutil.rmtree(cm.CRAWL_DIR)

    @pytest.mark.skipif(bool(os.getenv('CI', False)), reason='Skip in CI')
    def test_cloudflare_captcha_page(self):
        expected_pcaps = 2

        self.configure_crawler('WebFP', 'captcha_test')

        url = 'https://cloudflare.com/'
        job = crawler_mod.CrawlJob(self.job_config, [url])
        cm.CRAWL_DIR = os.path.join(TEST_DIRS,
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

    @pytest.mark.skipif(bool(os.getenv('CI', False)), reason='Skip in CI')
    def test_not_captcha_after_captcha(self):
        self.configure_crawler('WebFP', 'captcha_test')

        known_captcha_url = 'https://cloudflare.com'
        known_not_captcha_url = 'https://check.torproject.org/'
        urls = [known_captcha_url, known_not_captcha_url]
        job = crawler_mod.CrawlJob(self.job_config, urls)
        cm.CRAWL_DIR = os.path.join(TEST_DIRS,
                                    'test_not_captcha_after_captcha')
        self.run_crawl(job)

        for _dir in os.listdir(cm.CRAWL_DIR):
            marked_captcha = _dir.startswith('captcha_')
            is_torproject_dir = 'check.torproject.org' in _dir
            if is_torproject_dir:
                self.assertTrue(not marked_captcha)
            else:
                self.assertTrue(marked_captcha)

        shutil.rmtree(cm.CRAWL_DIR)

    @pytest.mark.skipif(bool(os.getenv('CI', False)), reason='Skip in CI')
    def test_captcha_not_captcha_2_batches(self):
        self.configure_crawler('WebFP', 'test_captcha_not_captcha_2_batches')

        known_captcha_url = 'https://cloudflare.com'
        known_not_captcha_url = 'https://check.torproject.org/'
        urls = [known_captcha_url, known_not_captcha_url]
        job = crawler_mod.CrawlJob(self.job_config, urls)
        cm.CRAWL_DIR = os.path.join(TEST_DIRS,
                                    'test_not_captcha_after_captcha')
        self.run_crawl(job)

        for _dir in os.listdir(cm.CRAWL_DIR):
            marked_captcha = _dir.startswith('captcha_')
            is_torproject_dir = 'check.torproject.org' in _dir
            if is_torproject_dir:
                self.assertTrue(not marked_captcha)
            else:
                self.assertTrue(marked_captcha)
        shutil.rmtree(cm.CRAWL_DIR)

    def test_website_in_capture_dir(self):
        self.configure_crawler('WebFP', 'captcha_test')

        url = 'https://cloudflare.com/'
        job = crawler_mod.CrawlJob(self.job_config, [url])
        cm.CRAWL_DIR = os.path.join(cm.TEST_DIR,
                                    'test_website_in_capture_dir')
        self.run_crawl(job)

        for _dir in os.listdir(cm.CRAWL_DIR):
            self.assertTrue('cloudflare.com' in _dir)
        shutil.rmtree(cm.CRAWL_DIR)

    def run_crawl(self, job):
        build_crawl_dirs()
        os.chdir(cm.CRAWL_DIR)
        try:
            self.crawler.crawl(job)  # we can pass batch and instance numbers
        finally:
            self.driver.quit()
            self.controller.quit()

    #@pytest.mark.skipif(bool(os.getenv('CI', False)), reason='Skip in CI')
    def test_middle(self):
        self.configure_crawler('Middle', 'captcha_test')
        job = crawler_mod.CrawlJob(self.job_config, TEST_URL_LIST)
        cm.CRAWL_DIR = os.path.join(TEST_DIRS, 'test_crawl')
        self.run_crawl(job)
        # TODO: test for more conditions...
        self.assertGreater(len(os.listdir(cm.CRAWL_DIR)), 0)
        shutil.rmtree(cm.CRAWL_DIR)


if __name__ == "__main__":
    unittest.main()
