import shutil
from contextlib import contextmanager
from os import environ
from os.path import join, isfile, isdir, dirname

import stem.process
from stem.control import Controller
from stem.util import term
from tbselenium.common import DEFAULT_TOR_DATA_PATH, DEFAULT_TOR_BINARY_PATH

import common as cm
import utils as ut


class TorController(object):
    def __init__(self,
                 tbb_path=None,
                 tor_binary_path=None,
                 tor_data_path=None,
                 torrc_dict={'controlport': '9051', 'socksport': '9050'},
                 pollute=True):
        assert (tbb_path or tor_binary_path and tor_data_path)
        if tbb_path:
            tbb_path = tbb_path.rstrip('/')
            tor_binary_path = join(tbb_path, DEFAULT_TOR_BINARY_PATH)
            tor_data_path = join(tbb_path, DEFAULT_TOR_DATA_PATH)

        # Make sure the paths exist
        assert (isfile(tor_binary_path) and isdir(tor_data_path))
        self.tor_binary_path = tor_binary_path
        self.tor_data_path = tor_data_path
        self.torrc_dict = torrc_dict
        self.controller = None
        self.tmp_tor_data_dir = None
        self.tor_process = None
        self.pollute = pollute
        self.control_port = int(self.torrc_dict['controlport'])
        self.socks_port = int(self.torrc_dict['socksport'])
        self.export_lib_path()

    def get_guard_ips(self):
        ips = []
        for circ in self.controller.get_circuits():
            # filter empty circuits out
            if len(circ.path) == 0:
                continue
            ip = self.controller.get_network_status(circ.path[0][0]).address
            if ip not in ips:
                ips.append(ip)
        return ips

    def get_all_guard_ips(self):
        for router_status in self.controller.get_network_statuses():
            if 'Guard' in router_status.flags:
                yield router_status.address

    def tor_log_handler(self, line):
        print(term.format(line))

    def restart_tor(self):
        """Kill current Tor process and run a new one."""
        self.kill_tor_proc()
        self.launch_tor_service()

    def export_lib_path(self):
        """Add the Tor Browser binary to the library path."""
        environ["LD_LIBRARY_PATH"] = dirname(self.tor_binary_path)

    def quit(self):
        """Kill Tor process."""
        if self.tor_process:
            self.tor_process.kill()
        if self.tmp_tor_data_dir and isdir(self.tmp_tor_data_dir):
            print("Removing tmp tor data dir")
            shutil.rmtree(self.tmp_tor_data_dir)

    def launch_tor_service(self):
        """Launch Tor service and return the process."""
        if self.pollute:
            self.tmp_tor_data_dir = ut.clone_dir_temporary(self.tor_data_path)
            self.torrc_dict.update({'DataDirectory': self.tmp_tor_data_dir})

        print("Tor config: %s" % self.torrc_dict)
        # the following may raise, make sure it's handled
        self.tor_process = stem.process.launch_tor_with_config(
            config=self.torrc_dict,
            init_msg_handler=self.tor_log_handler,
            tor_cmd=self.tor_binary_path,
            timeout=270
        )
        self.controller = Controller.from_port(port=self.control_port)
        self.controller.authenticate()
        return self.tor_process

    def close_all_streams(self):
        """Close all streams of a controller."""
        print("Closing all streams")
        try:
            with ut.timeout(cm.STREAM_CLOSE_TIMEOUT):
                for stream in self.controller.get_streams():
                    print("Closing stream %s %s %s " %
                          (stream.id, stream.purpose, stream.target_address))
                    self.controller.close_stream(stream.id)  # MISC reason
        except ut.TimeoutException:
            print("Closing streams timed out!")
        except:
            print("Exception closing stream")


    @contextmanager
    def launch(self):
        self.launch_tor_service()
        yield
        self.quit()


