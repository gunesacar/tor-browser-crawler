import argparse
import traceback
from logging import INFO, DEBUG
from os import stat
from os.path import isfile
from sys import maxsize, argv

import common as cm
import utils as ut
from log import wl_log
from tbcrawler.crawler import Crawler


def main():
    # Parse arguments
    args = parse_arguments()

    # Read URLs
    url_list = parse_url_list(args.url_list)

    # Get torrc matching experiment type
    torrc_dict = cm.TORRC_BY_TYPE[args.experiment]

    # Instantiate crawler
    crawler = Crawler(url_list, torrc_dict,
                      output=args.output,
                      experiment=args.experiment,
                      xvfb=args.xvfb,
                      capture_screen=True)

    # Run the crawl
    try:
        crawler.crawl(args.batches, args.instances,
                      start_line=args.start_line - 1)
    except KeyboardInterrupt:
        wl_log.warning("Keyboard interrupt! Quitting...")
    except Exception as e:
        wl_log.error("Exception: \n%s" % (traceback.format_exc()))
    finally:
        crawler.stop_crawl()


def parse_url_list(url_list):
    """Return list of urls from a file."""
    with url_list:
        url_acc = [line.strip() for line in url_list]
    return url_acc

def parse_arguments():
    # Parse arguments
    parser = argparse.ArgumentParser(description='Crawl a list of URLs in multiple batches.')

    # List of urls to be crawled
    parser.add_argument('-u', '--url-list',
                        type=argparse.FileType('r'), required=True,
                        help='Path to the file that contains the list of URLs \
                        to crawl.')
    parser.add_argument('-o', '--output',
                        help='Directory to dump the results (default=./results).',
                        default=cm.RESULTS_DIR)
    parser.add_argument('-b', '--tbb-path',
                        help="Path to the Tor Browser Bundle directory.",
                        default=cm.TBB_PATH)
    parser.add_argument("-e", "--experiment", choices=cm.EXP_TYPES,
                        help="Specifies the crawling methodology.",
                        default=cm.EXP_TYPE_WANG_AND_GOLDBERG)
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='increase output verbosity',
                        default=False)

    # For understanding batch and instance parameters please refer
    # to Wang and Goldberg's WPES'13 paper, Section 4.1.4
    parser.add_argument('--batches', type=int,
                        help='Number of batches in the crawl (default: %s)' % cm.NUM_BATCHES,
                        default=cm.NUM_BATCHES)
    parser.add_argument('--instances', type=int,
                        help='Number of instances to crawl for each web page (default: %s)' % cm.NUM_INSTANCES,
                        default=cm.NUM_INSTANCES)

    # Crawler features
    parser.add_argument('-x', '--xvfb', action='store_true',
                        help='Use XVFB (for headless testing)',
                        default=False)
    parser.add_argument('-c', '--capture-screen', action='store_true',
                        help='Capture page screenshots',
                        default=False)

    # Limit crawl
    parser.add_argument('--start', type=int,
                        help='Start crawling URLs from this line number: (default: 1).',
                        default=1)
    parser.add_argument('--stop', type=int,
                        help='Stop crawling URLs after this line number: (default: EOF).',
                        default=maxsize)

    # Parse arguments
    args = parser.parse_args()

    # Set verbose level
    wl_log.setLevel(DEBUG if args.verbose else INFO)
    del args.verbose

    wl_log.debug("Command line parameters: %s" % argv)

    return args


if __name__ == '__main__':
    main()
