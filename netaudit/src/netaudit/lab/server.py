"""SSH front-end for the lab: every simulated switch listens on its own TCP port.

It emulates enough of the IOS CLI for Ansible (network_cli + cisco.ios),
Netmiko and Oxidized: user/privileged/config modes, the enable password
prompt, `terminal ...`, show commands with `| include/exclude/begin/section`,
configuration with `interface`/`no`/`end`, `copy running-config
startup-config` and `write memory`.
"""

from __future__ import annotations

import logging
import re
import socket
import threading
import time
from typing import TYPE_CHECKING

import paramiko

from ..util import canonical_interface
from .configtree import KNOWN_GLOBAL_KEYWORDS
from .sim import Lab, load_lab

if TYPE_CHECKING:  # pragma: no cover
    from .sim import SimSwitch

log = logging.getLogger("netaudit.lab")
LOCK = threading.RLock()

# Commands valid inside `interface X`.  Anything else falls back to global
# configuration mode, exactly like IOS does when a global command is typed in a
# sub-mode.
INTERFACE_COMMANDS = re.compile(
    r"^(?:no |default )?(?:"
    r"switchport|description|shutdown|speed|duplex|channel-group|channel-protocol|storm-control|power inline|"
    r"load-interval|carrier-delay|keepalive|media-type|negotiation|srr-queue|priority-queue|service-policy|"
    r"auto qos|authentication|dot1x|mab|device-tracking|access-session|trust|mls qos|macro|"
    r"spanning-tree (?:portfast|bpduguard|bpdufilter|guard|link-type|cost|port-priority|"
    r"vlan \S+ (?:cost|port-priority)|mst \S+ (?:cost|port-priority))|"
    r"ip (?:address|helper-address|access-group|dhcp snooping|arp inspection|verify|igmp|ospf|pim|route-cache)|"
    r"cdp enable|lldp (?:transmit|receive)|udld port|logging event|snmp trap|errdisable detect"
    r")\b"
)
SUBMODE_COMMANDS = {
    "line": re.compile(
        r"^(?:no )?(?:login|transport|exec-timeout|password|logging synchronous|access-class|length|privilege|session-timeout|stopbits|width)\b"
    ),
    "vlan": re.compile(r"^(?:no )?(?:name|state|shutdown|remote-span|private-vlan)\b"),
    "mst": re.compile(r"^(?:no )?(?:name|revision|instance|abort|exit|show)\b"),
}
INVALID = "% Invalid input detected at '^' marker."


class _Auth(paramiko.ServerInterface):
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.exec_command: str | None = None
        self.ready = threading.Event()

    def check_auth_password(self, username, password):
        if username == self.username and password == self.password:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.ready.set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.exec_command = command.decode() if isinstance(command, bytes) else command
        self.ready.set()
        return True

    def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight):
        return True


class CliSession:
    """One interactive CLI session on one simulated switch."""

    def __init__(self, lab: Lab, sw: SimSwitch, channel, enable_secret: str):
        self.lab = lab
        self.sw = sw
        self.channel = channel
        self.enable_secret = enable_secret
        self.mode = "user"  # user | priv | config | config-if | config-sub
        self.parent: str | None = None
        self.sub_label = ""
        self.awaiting: str | None = None  # "enable-password" | "copy-destination"
        self.password_tries = 0
        self.snapshot = None
        self.closed = False

    # -- I/O --------------------------------------------------------------------
    def send(self, text: str) -> None:
        if self.closed:
            return
        try:
            self.channel.sendall(text.replace("\r\n", "\n").replace("\n", "\r\n").encode())
        except OSError:
            self.closed = True

    def prompt(self) -> str:
        name = self.sw.name
        return {
            "user": f"{name}>",
            "priv": f"{name}#",
            "config": f"{name}(config)#",
            "config-if": f"{name}(config-if)#",
            "config-sub": f"{name}(config-{self.sub_label})#",
        }[self.mode]

    def run(self) -> None:
        self.send(f"\r\n\r\n{self.prompt()}")
        buffer = ""
        last_cr = False
        while not self.closed:
            try:
                data = self.channel.recv(4096)
            except (OSError, EOFError):
                break
            if not data:
                break
            for char in data.decode(errors="ignore"):
                if char == "\n" and last_cr:
                    last_cr = False
                    continue
                last_cr = char == "\r"
                if char in "\r\n":
                    line, buffer = buffer, ""
                    self.send("\r\n")
                    self.handle_line(line)
                    if self.closed:
                        break
                    if self.awaiting == "enable-password":
                        self.send("Password: ")
                    elif self.awaiting == "copy-destination":
                        self.send("Destination filename [startup-config]? ")
                    else:
                        self.send(self.prompt())
                elif char == "\x03":  # Ctrl-C
                    buffer = ""
                    self.send("^C\r\n" + self.prompt())
                elif char == "\x1a":  # Ctrl-Z
                    buffer = ""
                    if self.mode.startswith("config"):
                        self._leave_config()
                    self.send("\r\n" + self.prompt())
                elif char in "\x7f\x08":
                    if buffer:
                        buffer = buffer[:-1]
                        if self.awaiting != "enable-password":
                            self.send("\b \b")
                elif char.isprintable() or char == "\t":
                    buffer += char
                    if self.awaiting != "enable-password":
                        self.send(char)
        self.closed = True
        try:
            self.channel.close()
        except OSError:
            pass

    # -- dispatch ------------------------------------------------------------------
    def handle_line(self, line: str) -> None:
        if self.awaiting == "enable-password":
            self.awaiting = None
            if line == self.enable_secret:
                self.mode = "priv"
                self.password_tries = 0
            else:
                self.password_tries += 1
                if self.password_tries < 3:
                    self.awaiting = "enable-password"
                else:
                    self.password_tries = 0
                    self.send("% Bad passwords\r\n")
            return
        if self.awaiting == "copy-destination":
            self.awaiting = None
            if line.strip() in ("", "startup-config"):
                with LOCK:
                    self.sw.startup = self.sw.cfg.text()
                self.send("Building configuration...\r\n[OK]\r\n")
            else:
                self.send("%Error opening " + line.strip() + " (Permission denied)\r\n")
            return
        line = line.strip()
        if not line or line.startswith("!"):
            return
        with LOCK:
            if self.mode.startswith("config"):
                self.config_line(line)
            else:
                self.exec_line(line)

    def exec_line(self, line: str) -> None:
        words = line.split()
        verb = words[0].lower()
        if "enable".startswith(verb) and len(verb) >= 2:
            if self.mode == "user":
                self.awaiting = "enable-password"
            return
        if verb in ("exit", "logout", "quit"):
            self.closed = True
            try:
                self.channel.close()
            except OSError:
                pass
            return
        if "terminal".startswith(verb) and len(verb) >= 3:
            return
        if verb == "disable":
            self.mode = "user"
            return
        if self.mode == "user":
            if re.match(r"^sh(ow?)?\s+priv", line):
                self.send("Current privilege level is 1\r\n")
                return
            if re.match(r"^sh(ow?)?\s+ver", line):
                self.send(self.lab.run(self.sw.name, "show version") + "\r\n")
                return
            self.send(INVALID + "\r\n")
            return
        if re.match(r"^conf(i(g(u(r(e)?)?)?)?)?\s+t(e(r(m(i(n(a(l)?)?)?)?)?)?)?$", line):
            self.send("Enter configuration commands, one per line.  End with CNTL/Z.\r\n")
            self.mode = "config"
            self.snapshot = self.lab.snapshot(self.sw)
            return
        if re.match(r"^copy\s+run(ning-config)?\s+start(up-config)?$", line):
            self.awaiting = "copy-destination"
            return
        if re.match(r"^wr(i(t(e)?)?)?(\s+mem(o(r(y)?)?)?)?$", line):
            self.sw.startup = self.sw.cfg.text()
            self.send("Building configuration...\r\n[OK]\r\n")
            return
        if verb == "reload":
            self.send("% Reload is not available in the lab\r\n")
            return
        if verb == "clear":
            return
        if verb == "ping":
            self.send(
                "Type escape sequence to abort.\r\nSuccess rate is 100 percent (5/5), round-trip min/avg/max = 1/1/2 ms\r\n"
            )
            return
        if re.match(r"^sh(ow?)?\s+priv", line):
            self.send("Current privilege level is 15\r\n")
            return
        if verb.startswith("sh"):
            output = self.lab.run(self.sw.name, line)
            if output is None:
                self.send(INVALID + "\r\n")
            else:
                self.send(output.rstrip("\n") + "\r\n")
            return
        self.send(INVALID + "\r\n")

    def _leave_config(self) -> None:
        self.mode = "priv"
        self.parent = None
        if self.snapshot is not None:
            self.lab.config_changed(self.sw, self.snapshot)
            self.snapshot = None
        self.sw.log("%SYS-5-CONFIG_I: Configured from console by labadmin on vty0 (10.99.0.250)")

    def config_line(self, line: str) -> None:
        cfg = self.sw.cfg
        words = line.split()
        verb = words[0].lower()
        if verb == "end":
            self._leave_config()
            return
        if verb == "exit":
            if self.mode == "config":
                self._leave_config()
            else:
                self.mode, self.parent = "config", None
            return
        if verb == "do":
            self.exec_line(line[3:].strip())
            return
        negate = verb in ("no", "default")
        body = " ".join(words[1:]) if negate else line
        first = (words[1] if negate and len(words) > 1 else verb).lower()

        if not negate and first == "interface":
            name = canonical_interface(" ".join(words[1:]))
            if name not in self.sw.ports and not re.match(r"^(Port-channel|Vlan|Loopback)\d+$", name):
                self.send(INVALID + "\r\n")
                return
            self.mode, self.parent = "config-if", f"interface {name}"
            cfg.section(self.parent, create=True)
            return
        if not negate and (first in ("line", "vlan") or line.startswith("spanning-tree mst configuration")):
            self.mode, self.parent = "config-sub", line
            self.sub_label = {"line": "line", "vlan": "vlan"}.get(first, "mst")
            cfg.section(self.parent, create=True)
            return

        if self.mode == "config-if" and INTERFACE_COMMANDS.match(line):
            if negate:
                cfg.remove_child(self.parent, body)
            else:
                cfg.set_child(self.parent, line, edge_portfast=self.sw.edge_syntax)
                if line == "shutdown":
                    # Shutting a port down clears its err-disabled state, as on IOS.
                    self.sw.errdisabled.pop(self.parent.split(" ", 1)[1], None)
            self.lab.check_bpduguard(self.sw)
            return
        if self.mode == "config-sub" and SUBMODE_COMMANDS.get(self.sub_label, re.compile("$^")).match(line):
            if negate:
                cfg.remove_child(self.parent, body)
            else:
                cfg.set_child(self.parent, line)
            return
        # Global configuration (also reached from a sub-mode, which IOS then leaves).
        if first not in KNOWN_GLOBAL_KEYWORDS:
            self.send(INVALID + "\r\n")
            return
        error = self._validate_global(body if not negate else "")
        if error:
            self.send(error + "\r\n")
            return
        self.mode, self.parent = "config", None
        if negate:
            cfg.remove_global(body)
        else:
            cfg.set_global(line)

    @staticmethod
    def _validate_global(line: str) -> str | None:
        if m := re.match(r"^spanning-tree mode (\S+)$", line):
            if m.group(1) not in ("pvst", "rapid-pvst", "mst"):
                return INVALID
        if m := re.match(r"^spanning-tree vlan (\S+) priority (\d+)$", line):
            value = int(m.group(2))
            if value % 4096 or value > 61440:
                return "% Bridge Priority must be in increments of 4096.\n% Allowed values are:\n  0     4096  8192  12288 16384 20480 24576 28672\n  32768 36864 40960 45056 49152 53248 57344 61440"
        return None


def _handle(lab: Lab, sw: SimSwitch, client: socket.socket, host_key: paramiko.PKey) -> None:
    creds = lab.ssh
    transport = paramiko.Transport(client)
    transport.add_server_key(host_key)
    transport.local_version = "SSH-2.0-Cisco-1.25"
    if sw.legacy_ssh:
        options = transport.get_security_options()
        options.kex = ("diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1")
        options.key_types = ("ssh-rsa",)
        options.ciphers = ("aes128-cbc", "aes256-cbc", "3des-cbc")
        options.digests = ("hmac-sha1",)
    server = _Auth(creds.get("username", "labadmin"), str(creds.get("password", "labpass")))
    try:
        transport.start_server(server=server)
        channel = transport.accept(30)
        if channel is None:
            return
        server.ready.wait(10)
        session = CliSession(lab, sw, channel, str(creds.get("enable", "labenable")))
        if server.exec_command:
            session.mode = "priv"
            with LOCK:
                output = lab.run(sw.name, server.exec_command)
            channel.sendall(((output or INVALID) + "\n").replace("\n", "\r\n").encode())
            channel.send_exit_status(0)
            channel.close()
            return
        session.run()
    except Exception as exc:  # pragma: no cover - network errors from clients
        log.debug("session error on %s: %s", sw.name, exc)
    finally:
        time.sleep(0.1)
        transport.close()


def _listen(lab: Lab, sw: SimSwitch, address: str, port: int, host_key: paramiko.PKey) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((address, port))
    server.listen(32)
    while True:
        client, _ = server.accept()
        threading.Thread(target=_handle, args=(lab, sw, client, host_key), daemon=True).start()


def _host_key(path: str | None) -> paramiko.PKey:
    """Load the lab's SSH host key, creating it on first use, so restarts keep the same key."""
    if path:
        try:
            return paramiko.RSAKey.from_private_key_file(path)
        except (OSError, paramiko.SSHException):
            pass
    key = paramiko.RSAKey.generate(2048)
    if path:
        try:
            key.write_private_key_file(path)
        except OSError as exc:
            log.warning("could not save host key to %s: %s", path, exc)
    return key


def serve(
    topology: str, listen: str = "0.0.0.0", base_port: int | None = None, host_key_file: str | None = None
) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    lab = load_lab(topology)
    base = base_port or int(lab.ssh.get("base_port", 2201))
    host_key = _host_key(host_key_file)
    threads = []
    for index, (name, sw) in enumerate(lab.switches.items()):
        port = base + index
        thread = threading.Thread(target=_listen, args=(lab, sw, listen, port, host_key), daemon=True)
        thread.start()
        threads.append(thread)
        log.info(
            "%-10s listening on %s:%d%s", name, listen, port, " (legacy SSH algorithms only)" if sw.legacy_ssh else ""
        )
    log.info(
        "lab ready: user %s, password %s, enable %s",
        lab.ssh.get("username"),
        lab.ssh.get("password"),
        lab.ssh.get("enable"),
    )
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        return 0
