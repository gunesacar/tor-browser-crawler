import os
import subprocess
import time
import psutil

import common as cm
import utils as ut
from log import wl_log

DUMPCAP_START_TIMEOUT = 10.0


class Sniffer(object):
    """Capture network traffic using dumpcap."""

    def __init__(self, device, path="/dev/null", filter=""):
        self.pcap_file = path
        self.pcap_filter = filter
        self.device = device
        self.p0 = None
        self.is_recording = False

    def set_pcap_path(self, pcap_filename):
        """Set filename and filter options for capture."""
        self.pcap_file = pcap_filename

    def set_capture_filter(self, _filter):
        self.pcap_filter = _filter

    def get_pcap_path(self):
        """Return capture (pcap) filename."""
        return self.pcap_file

    def get_capture_filter(self):
        """Return capture filter."""
        return self.pcap_filter

    def start_capture(self, device='', pcap_path=None, pcap_filter=""):
        """Start capture. Configure sniffer if arguments are given."""
        if pcap_filter:
            self.set_capture_filter(pcap_filter)
        if pcap_path:
            self.set_pcap_path(pcap_path)
        prefix = ""
        command = '{}dumpcap -P -a duration:{} -a filesize:{} -i {} -s 0 -f \'{}\' -w {}'\
            .format(prefix, cm.SOFT_VISIT_TIMEOUT, cm.MAX_DUMP_SIZE,
                    self.device, self.pcap_filter, self.pcap_file)
        wl_log.info(command)
        self.p0 = subprocess.Popen(command, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, shell=True)
        timeout = DUMPCAP_START_TIMEOUT  # in seconds
        while timeout > 0 and not self.is_dumpcap_running():
            time.sleep(0.1)
            timeout -= 0.1
        if timeout < 0:
            raise DumpcapTimeoutError()
        else:
            wl_log.debug("dumpcap started in %s seconds" %
                         (DUMPCAP_START_TIMEOUT - timeout))

        self.is_recording = True

    def is_dumpcap_running(self):
        if "dumpcap" in psutil.Process(self.p0.pid).cmdline():
            return self.p0.returncode is None
        for proc in ut.gen_all_children_procs(self.p0.pid):
            if "dumpcap" in proc.cmdline():
                return True
        return False

    def stop_capture(self):
        """Kill the dumpcap process."""
        ut.kill_all_children(self.p0.pid)  # self.p0.pid is the shell pid
        self.p0.kill()
        self.is_recording = False
        captcha_filepath = ut.capture_filepath_to_captcha(self.pcap_file)
        if os.path.isfile(self.pcap_file):
            wl_log.info('Dumpcap killed. Capture size: %s Bytes %s' %
                        (os.path.getsize(self.pcap_file), self.pcap_file))
        elif os.path.isfile(captcha_filepath):
            wl_log.info('Dumpcap killed, file renamed to captcha_*. Capture size: %s Bytes %s' %
                        (os.path.getsize(captcha_filepath), captcha_filepath))
        else:
            wl_log.warning('Dumpcap killed but cannot find capture file: %s or %s'
                           % (self.pcap_file, captcha_filepath))

    def __enter__(self):
        self.start_capture()
        return self

    def __exit__(self, type, value, traceback):
        self.stop_capture()


class DumpcapTimeoutError(Exception):
    pass
