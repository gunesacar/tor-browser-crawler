import argparse
import ConfigParser
import sys
import traceback
import pickle
from contextlib import contextmanager
from logging import INFO, DEBUG
from os import stat, chdir
from os.path import isfile, join, abspath
from shutil import copyfile
from sys import maxsize, argv
from urlparse import urlparse

from tbselenium.tbdriver import TorBrowserDriver
from tbselenium.common import USE_RUNNING_TOR

import common as cm
import utils as ut
import crawler as crawler_mod
from log import add_log_file_handler
from log import wl_log, add_symlink
from torcontroller import TorController


def run():
    # Parse arguments
    args, config = parse_arguments()

    # build dirs
    build_crawl_dirs()

    # Read URLs
    if isfile(args.urls):
	    url_list = read_list_urls(args.urls, args.start, args.stop)
    else:
        try:
            url_list = args.urls.split(',')
        except Exception as e:
            wl_log.error("ERROR: expects a string with comma-separated list "
                         "of URLs of a path to file")
    host_list = [urlparse(url).hostname for url in url_list]

    # Configure logger
    add_log_file_handler(wl_log, cm.DEFAULT_CRAWL_LOG)

    # Configure controller
    torrc_config = ut.get_dict_subconfig(config, args.config, "torrc")
    controller = TorController(cm.TBB_DIR,
                               torrc_dict=torrc_config,
                               pollute=False)

    # Configure browser
    ffprefs = ut.get_dict_subconfig(config, args.config, "ffpref")
    ffprefs = ut.set_dict_value_types(ffprefs)
    print(ffprefs)
    addons_path = abspath(args.addons_dir) if args.addons_dir else None
    driver = TorBrowserWrapper(cm.TBB_DIR,
                               tbb_logfile_path=cm.DEFAULT_FF_LOG,
                               tor_cfg=USE_RUNNING_TOR,
                               pref_dict=ffprefs,
                               addons_dir=addons_path,
                               socks_port=int(torrc_config['socksport']),
                               canvas_allowed_hosts=host_list)

    # Instantiate crawler
    crawl_type = getattr(crawler_mod, "Crawler" + args.type)
    crawler = crawl_type(driver, controller,
                         device=args.device,
                         screenshots=args.screenshots)

    # Configure crawl
    if args.recover_file is not None and isfile(args.recover_file):
        with open(args.recover_file) as fchkpt:
            job = pickle.load(fchkpt)
            wl_log.info("Job recovered: %s" % str(job))
    else:
        job_config = ut.get_dict_subconfig(config, args.config, "job")
        job = crawler_mod.CrawlJob(job_config, url_list)

    # Run display
    xvfb_display = setup_virtual_display(args.virtual_display)

    # Run the crawl
    chdir(cm.CRAWL_DIR)
    try:
        crawler.crawl(job)
    except KeyboardInterrupt:
        wl_log.warning("Keyboard interrupt! Quitting...")
        sys.exit(-1)
    except Exception as e:
	wl_log.error("ERROR: unknown exception while crawling: %s" % e)
    finally:
        #driver.quit()
        #controller.quit()
        # Post crawl
        post_crawl()

        # Close display
        ut.stop_xvfb(xvfb_display)

    # die
    wl_log.info("[tbcrawler] the crawl has finished.")
    sys.exit(0)

def setup_virtual_display(virt_display):
    """Start a virtual display with the given dimensions (if requested)."""
    if virt_display:
        w, h = (int(dim) for dim in virt_display.lower().split("x"))
        return ut.start_xvfb(w, h)
    else:
        return ut.start_xvfb()

def post_crawl():
    """Operations after the crawl."""
    # TODO: pack crawl
    # TODO: sanity checks
    pass


def build_crawl_dirs():
    # build crawl directory
    ut.create_dir(cm.RESULTS_DIR)
    ut.create_dir(cm.CRAWL_DIR)
    ut.create_dir(cm.LOGS_DIR)
    copyfile(cm.CONFIG_FILE, join(cm.LOGS_DIR, 'config.ini'))
    add_symlink(join(cm.RESULTS_DIR, 'latest_crawl'), cm.CRAWL_DIR)


def read_list_urls(file_path, start, stop):
    """Return list of urls from a file."""
    assert isfile(file_path)  # URL file does not exist
    assert not stat(file_path).st_size == 0  # URL file is empty
    url_list = []
    try:
        with open(file_path) as f:
            file_contents = f.read()
            url_list = file_contents.splitlines()
            url_list = url_list[start - 1:stop]
    except Exception as e:
        ut.die("ERROR: while parsing URL list: {} \n{}".format(e, traceback.format_exc()))
    return url_list


def parse_arguments():
    # Read configuration file
    config = ConfigParser.RawConfigParser()
    config.read(cm.CONFIG_FILE)

    # Parse arguments
    parser = argparse.ArgumentParser(description='Crawl a list of URLs in multiple batches.')

    # List of urls to be crawled
    parser.add_argument('-u', '--urls', required=True,
                        help='Path to the file that contains the list of URLs to crawl,'
                             ' or a comma-separated list of URLs.',
                        default=cm.LOCALIZED_DATASET)
    parser.add_argument('-t', '--type',
                        choices=cm.CRAWLER_TYPES,
                        help="Crawler type to use for this crawl.",
                        default='Base')
    parser.add_argument('-o', '--output',
                        help='Directory to dump the results (default=./results).',
                        default=cm.CRAWL_DIR)
    parser.add_argument('-a', '--addons_dir',
                        help='Directory with the add-ons to be installed (default=None).',
                        default=None)
    parser.add_argument('-c', '--config',
                        help="Crawler tor driver and controller configurations.",
                        choices=config.sections(),
                        default="default")
    parser.add_argument('-b', '--tbb-path',
                        help="Path to the Tor Browser Bundle directory.",
                        default=cm.TBB_DIR)
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='increase output verbosity',
                        default=False)
    parser.add_argument('-r', '--recover-file',
                        help="File with checkpoint to recover from.",
                        default=None)

    # Crawler features
    parser.add_argument('-x', '--virtual-display',
                        help='Dimensions of the virtual display, eg 1200x800',
                        default='')
    parser.add_argument('-s', '--screenshots', action='store_true',
                        help='Capture page screenshots',
                        default=False)
    parser.add_argument('-d', '--device',
                        help='Interface to sniff the network traffic',
                        default='eth0')

    # Limit crawl
    parser.add_argument('--start', type=int,
                        help='Select URLs from this line number: (default: 1).',
                        default=1)
    parser.add_argument('--stop', type=int,
                        help='Select URLs after this line number: (default: EOF).',
                        default=maxsize)

    # Parse arguments
    args = parser.parse_args()

    # Set verbose level
    wl_log.setLevel(DEBUG if args.verbose else INFO)
    del args.verbose

    # Change results dir if output
    cm.CRAWL_DIR = args.output
    del args.output

    wl_log.debug("Command line parameters: %s" % argv)
    return args, config


class TorBrowserWrapper(object):
    """Wraps the TorBrowserDriver to configure it at the constructor
    and run it with the `launch` method.

    We might consider to change the TorBrowserDriver itself to follow
    torcontroller and stem behaviour: init configures and a method is
    used to launch driver/controller, and this method is the one used
    to implement the contextmanager.
    """
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.driver = None

    def __getattr__(self, item):
        if self.driver is None:
            return
        if item == "launch":
            return getattr(self, item)
        return getattr(self.driver, item)

    @contextmanager
    def launch(self):
        self.driver = TorBrowserDriver(*self.args, **self.kwargs)
        yield self.driver
        self.driver.quit()


if __name__ == '__main__':
    run()
