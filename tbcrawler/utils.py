import signal
from contextlib import contextmanager
from shutil import copyfile
from distutils.dir_util import copy_tree
from os import makedirs
from os.path import exists, join, split


import psutil
from pyvirtualdisplay import Display
from scapy.all import PcapReader, wrpcap

from common import TimeoutException
from tbcrawler import common as cm


def create_dir(dir_path):
    """Create a directory if it doesn't exist."""
    if not exists(dir_path):
        makedirs(dir_path)
    return dir_path


def clone_dir_temporary(dir_path):
    """Makes a temporary copy of a directory."""
    import tempfile
    tempdir = tempfile.mkdtemp()
    copy_tree(dir_path, tempdir)
    return tempdir


def gen_all_children_procs(parent_pid):
    """Iterator over the children of a process."""
    parent = psutil.Process(parent_pid)
    for child in parent.children(recursive=True):
        yield child


def kill_all_children(parent_pid):
    """Kill all child process of a given parent."""
    for child in gen_all_children_procs(parent_pid):
        child.kill()


def get_dict_subconfig(config, section, prefix):
    """Return options in config for options with a `prefix` keyword."""
    return {option.split()[1]: config.get(section, option)
            for option in config.options(section) if option.startswith(prefix)}


def str2bool(v):
  return v.lower() in ("yes", "true", "t", "1")


def set_dict_value_types(d):
    typed_d = []
    for k, v in d.items():
        typed_v = v
        for t in [int, float, str2bool]:
            try:
                typed_v = t(v)
            except ValueError:
                pass
            else:
                break
        typed_d.append((k, typed_v))
    return dict(typed_d)


@contextmanager
def timeout(seconds):
    """From: http://stackoverflow.com/a/601168/1336939"""
    def signal_handler(signum, frame):
        raise TimeoutException("Timed out!")

    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)


def filter_pcap(pcap_path, iplist, strip=False, clean=True):
    orig_pcap = pcap_path + ".original"
    copyfile(pcap_path, orig_pcap)
    with PcapReader(orig_pcap) as preader:
        pcap_filtered = []
        for p in preader:
            if 'TCP' in p:
                ip = p.payload
                if strip:
                    p['TCP'].remove_payload()  # stip payload (encrypted)
                if ip.dst in iplist or ip.src in iplist:
                    pcap_filtered.append(p)
    wrpcap(pcap_path, pcap_filtered)


def has_captcha(page_source):
    keywords = ['recaptcha_submit',
                'manual_recaptcha_challenge_field']
    return any(keyword in page_source for keyword in keywords)


def capture_dirpath_to_captcha(capture_dir_filepath):
    root_dir, capture_dir = split(capture_dir_filepath)
    return join(root_dir, 'captcha_' + capture_dir)


def capture_filepath_to_captcha(capture_filepath):
    dirname, filename = split(capture_filepath)
    crawl_dir, capture_dir = split(dirname)
    return join(crawl_dir, 'captcha_' + capture_dir, filename)


def start_xvfb(win_width=cm.DEFAULT_XVFB_WIN_W,
               win_height=cm.DEFAULT_XVFB_WIN_H):
    xvfb_display = Display(visible=0, size=(win_width, win_height))
    xvfb_display.start()
    return xvfb_display


def stop_xvfb(xvfb_display):
    if xvfb_display:
        xvfb_display.stop()
