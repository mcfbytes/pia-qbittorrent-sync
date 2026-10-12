import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pia_qbittorrent_sync as sync  # noqa: E402

WG_CONF = """[Interface]
Address = 10.1.2.3
PrivateKey = PRIVKEY
DNS = 10.0.0.243

[Peer]
PublicKey = OLDKEY
AllowedIPs = 0.0.0.0/0
Endpoint = 1.2.3.4:1337
PersistentKeepalive = 25
"""


def region(rid, pf, hosts, offline=False):
    return {'id': rid, 'name': rid, 'port_forward': pf, 'offline': offline,
            'servers': {'wg': [{'ip': ip, 'cn': cn} for cn, ip in hosts],
                        'meta': [{'ip': '9.9.9.9', 'cn': 'm'}]}}


class RankCandidatesTest(unittest.TestCase):
    regions = [
        region('nl', True, [('nl1', '1.1.1.1'), ('nl2', '1.1.1.2')]),
        region('de', True, [('de1', '2.2.2.1')]),
        region('us', False, [('us1', '3.3.3.1')]),
        region('se', True, [('se1', '4.4.4.1')], offline=True),
        region('fr', True, [('fr1', '5.5.5.1')]),
    ]

    def names(self, current, avoid=(), lat=None):
        lat = lat or {'nl': 0.05, 'de': 0.01, 'us': 0.001, 'se': 0.001, 'fr': 0.09}
        return [c.hostname for c in sync.rank_candidates(self.regions, current, set(avoid), lat)]

    def test_excludes_non_port_forwarding_and_offline(self):
        out = self.names(None)
        self.assertNotIn('us1', out)
        self.assertNotIn('se1', out)

    def test_same_region_first_then_latency(self):
        self.assertEqual(self.names('nl1'), ['nl2', 'de1', 'fr1'])

    def test_avoid_and_unreachable_regions(self):
        self.assertEqual(self.names('nl1', avoid={'nl2'}, lat={'de': 0.2}), ['de1'])


class FileRewriteTest(unittest.TestCase):
    def test_hosts_replaces_managed_and_shadowing_lines(self):
        text = f"127.0.0.1 localhost\n9.9.9.9 old1 {sync.HOSTS_MARKER}\n8.8.8.8 new1\n8.8.8.8 other new1\n"
        out = sync.render_hosts(text, 'new1', '1.1.1.1')
        self.assertEqual(out, f"127.0.0.1 localhost\n8.8.8.8 other new1\n1.1.1.1 new1 {sync.HOSTS_MARKER}\n")
        self.assertEqual(sync.render_hosts(out, 'new1', '1.1.1.1'), out)

    def test_hosts_hostname_is_lowercased(self):
        out = sync.render_hosts('8.8.8.8 Server-1-2a\n', 'Server-1-2a', '1.1.1.1')
        self.assertEqual(out, f'1.1.1.1 server-1-2a {sync.HOSTS_MARKER}\n')

    def test_env_file_keeps_style(self):
        text = 'export A="1"  # c\nPIA_GATEWAY="10.0.0.1"  # gw\nexport PIA_HOSTNAME=old\nB=2\n'
        out = sync.update_env_file(text, {'PIA_GATEWAY': '5.5.5.5', 'PIA_HOSTNAME': 'new9', 'NEW': 'x'})
        self.assertEqual(out, 'export A="1"  # c\nPIA_GATEWAY="5.5.5.5"  # gw\n'
                              'export PIA_HOSTNAME=new9\nB=2\nNEW="x"\n')

    def test_wg_config(self):
        self.assertEqual(sync.wg_private_key(WG_CONF), 'PRIVKEY')
        out = sync.rewrite_wg_config(WG_CONF, '10.9.9.9', 'NEWKEY', '5.6.7.8:1337')
        self.assertIn('Address = 10.9.9.9', out)
        self.assertIn('PublicKey = NEWKEY', out)
        self.assertIn('Endpoint = 5.6.7.8:1337', out)
        self.assertIn('PrivateKey = PRIVKEY', out)
        self.assertIn('DNS = 10.0.0.243', out)
        with self.assertRaises(ValueError):
            sync.rewrite_wg_config('[Interface]\nPrivateKey = x\n', 'a', 'b', 'c')

    def test_parse_server_list_and_expiry(self):
        raw = json.dumps({'regions': [{'id': 'x'}]}) + '\n\nc2lnbmF0dXJl'
        self.assertEqual(sync.parse_server_list(raw), [{'id': 'x'}])
        self.assertEqual(sync._parse_expiry('2026-01-02T03:04:05.123456789Z').microsecond, 123456)


class FailoverTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        d = Path(self.dir.name)
        self.hosts, self.wg, self.env = d / 'hosts', d / 'wg0.conf', d / 'conf'
        self.hosts.write_text('127.0.0.1 localhost\n')
        self.wg.write_text(WG_CONF)
        self.env.write_text('PIA_GATEWAY="1.2.3.4"\nPIA_HOSTNAME="nl1"\n')
        ca = d / 'ca.crt'
        ca.write_text('x')
        self.cfg = sync.Config.from_env({
            'PIA_USERNAME': 'p1', 'PIA_PASSWORD': 'pw', 'PIA_CA_CERT': str(ca),
            'PIA_TOKEN_FILE': str(d / 'token'), 'PIA_GATEWAY': '1.2.3.4', 'PIA_HOSTNAME': 'nl1',
            'QBITTORRENT_USERNAME': 'u', 'QBITTORRENT_PASSWORD': 'strongpw',
            'PIA_HOSTS_FILE': str(self.hosts), 'PIA_WG_CONFIG': str(self.wg),
            'PIA_CONFIG_FILE': str(self.env),
            'PIA_WG_DOWN_CMD': 'true', 'PIA_WG_UP_CMD': 'true',
        })
        patcher = mock.patch.object(sync, 'pia_session')
        patcher.start()
        self.addCleanup(patcher.stop)
        self.pia = sync.PIAPortForwarder(self.cfg)
        self.pia.get_token = lambda: "tok"  # never hit the real PIA API from tests
        self.fo = sync.WireGuardFailover(self.cfg, self.pia)
        self.regions = [region('nl', True, [('nl1', '1.1.1.1')]), region('de', True, [('de1', '2.2.2.1')])]

    def tearDown(self):
        self.dir.cleanup()

    def patches(self, add_key):
        return mock.patch.multiple(
            self.fo, _fetch_regions=lambda: self.regions,
            _wg_public_key=lambda k: 'PUB', _add_key=add_key)

    def test_successful_switch(self):
        answer = {'status': 'OK', 'peer_ip': '10.5.5.5', 'server_key': 'SK', 'server_port': 1337}
        with self.patches(lambda s, t, p: answer), \
                mock.patch.object(sync, 'measure_region_latencies', lambda r: {'nl': 1, 'de': 0.1}), \
                mock.patch.object(sync.time, 'sleep'):
            server = self.fo.switch()
        self.assertEqual(server.hostname, 'de1')
        self.assertIn('2.2.2.1 de1', self.hosts.read_text())
        self.assertIn('Endpoint = 2.2.2.1:1337', self.wg.read_text())
        self.assertEqual(self.env.read_text(), 'PIA_GATEWAY="2.2.2.1"\nPIA_HOSTNAME="de1"\n')
        self.assertEqual((self.pia.hostname, self.pia.gateway), ('de1', '2.2.2.1'))

    def test_failed_switch_restores_hosts(self):
        with self.patches(lambda s, t, p: None), \
                mock.patch.object(sync, 'measure_region_latencies', lambda r: {'nl': 1, 'de': 0.1}):
            self.assertIsNone(self.fo.switch())
        self.assertIn('1.2.3.4 nl1', self.hosts.read_text())
        self.assertNotIn('de1', self.hosts.read_text())
        self.assertEqual(self.wg.read_text(), WG_CONF)
        self.assertEqual(self.pia.hostname, 'nl1')

    def test_rollback_when_tunnel_wont_come_up(self):
        answer = {'status': 'OK', 'peer_ip': '10.5.5.5', 'server_key': 'SK', 'server_port': 1337}
        calls = []
        self.fo._run = lambda cmd: calls.append(cmd) or len(calls) != 2  # 1st=down ok, 2nd=up fails
        with self.patches(lambda s, t, p: answer), \
                mock.patch.object(sync, 'measure_region_latencies', lambda r: {'nl': 1, 'de': 0.1}):
            self.assertIsNone(self.fo.switch())
        self.assertEqual(self.wg.read_text(), WG_CONF)
        self.assertEqual(self.env.read_text(), 'PIA_GATEWAY="1.2.3.4"\nPIA_HOSTNAME="nl1"\n')
        self.assertIn('1.2.3.4 nl1', self.hosts.read_text())


class ServiceTest(unittest.TestCase):
    def test_failover_triggers_after_timeout_only(self):
        cfg = mock.Mock(failover_timeout=300)
        svc = sync.PIAUpdaterService.__new__(sync.PIAUpdaterService)
        svc.cfg, svc.down_since, svc.next_failover_at, svc.failover_failures = cfg, None, 0.0, 0
        svc.pia = mock.Mock(reachable=False)
        svc.failover = mock.Mock()
        svc.failover.switch.return_value = object()
        with mock.patch.object(sync.time, 'monotonic', return_value=1000.0):
            svc._track_connectivity(True)
        svc.failover.switch.assert_not_called()
        with mock.patch.object(sync.time, 'monotonic', return_value=1301.0):
            svc._track_connectivity(True)
        svc.failover.switch.assert_called_once()
        self.assertIsNone(svc.down_since)

    def test_failed_failover_backs_off(self):
        svc = sync.PIAUpdaterService.__new__(sync.PIAUpdaterService)
        svc.cfg, svc.down_since, svc.next_failover_at, svc.failover_failures = mock.Mock(failover_timeout=300), 0.0, 0.0, 0
        svc.pia = mock.Mock(reachable=False)
        svc.failover = mock.Mock()
        svc.failover.switch.return_value = None
        with mock.patch.object(sync.time, 'monotonic', return_value=1000.0):
            svc._track_connectivity(True)
            self.assertEqual(svc.next_failover_at, 1060.0)
        with mock.patch.object(sync.time, 'monotonic', return_value=1060.0):
            svc._track_connectivity(True)
            self.assertEqual(svc.next_failover_at, 1180.0)
        self.assertEqual(svc.failover.switch.call_count, 2)

    def test_recovery_resets_timer(self):
        svc = sync.PIAUpdaterService.__new__(sync.PIAUpdaterService)
        svc.down_since, svc.pia = 5.0, mock.Mock(reachable=True)
        svc._track_connectivity(True)
        self.assertIsNone(svc.down_since)


class PIASessionTest(unittest.TestCase):
    def test_strict_x509_is_off_but_verification_is_on(self):
        import ssl
        ca = str(Path(__file__).parent / 'ca.rsa.4096.crt')
        adapter = sync.pia_session(ca).get_adapter('https://example.com')
        ctx = adapter._context
        self.assertFalse(ctx.verify_flags & ssl.VERIFY_X509_STRICT)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)


class TokenRequestTest(unittest.TestCase):
    def test_credentials_sent_as_multipart(self):
        cfg = mock.Mock(token_file='/nonexistent/dir/token', pia_username='p1', pia_password='pw',
                        ca_cert='x', gateway='g', hostname='h')
        with mock.patch.object(sync, 'pia_session'):
            pia = sync.PIAPortForwarder(cfg)
        reply = mock.Mock(status_code=200)
        reply.json.return_value = {'token': 'T'}
        with mock.patch.object(sync.requests, 'post', return_value=reply) as post, \
                mock.patch.object(sync, 'write_private_file'):
            self.assertEqual(pia.get_token(force_refresh=True), 'T')
        kwargs = post.call_args.kwargs
        self.assertNotIn('data', kwargs)
        self.assertEqual(kwargs['files'], {'username': (None, 'p1'), 'password': (None, 'pw')})


class QBittorrentLoginTest(unittest.TestCase):
    def login(self, status, text):
        client = sync.QBittorrentClient('http://x', 'u', 'p')
        client.session.post = lambda *a, **k: mock.Mock(status_code=status, text=text)
        return client.login()

    def test_login_responses(self):
        self.assertTrue(self.login(200, 'Ok.'))
        self.assertTrue(self.login(204, ''))
        self.assertFalse(self.login(200, 'Fails.'))
        self.assertFalse(self.login(403, ''))


class ConfigTest(unittest.TestCase):
    def test_errors_collected(self):
        with self.assertRaises(sync.ConfigError) as cm:
            sync.Config.from_env({'LOG_LEVEL': 'LOUD', 'CHECK_INTERVAL': '0',
                                  'QBITTORRENT_PASSWORD': ' AdminAdmin ', 'PIA_TOKEN_FILE': '/nonexistent'})
        text = ' | '.join(cm.exception.errors)
        for needle in ('LOG_LEVEL', 'CHECK_INTERVAL', 'PIA credentials', 'PIA_CA_CERT',
                       'QBITTORRENT_USERNAME is not set', 'QBITTORRENT_PASSWORD is set'):
            self.assertIn(needle, text)

    def test_credentials_are_kept_verbatim(self):
        self.setUpFiles()
        cfg = sync.Config.from_env({
            'PIA_USERNAME': 'p1', 'PIA_PASSWORD': ' Pia&Pass\\1 ', 'PIA_CA_CERT': self.ca,
            'QBITTORRENT_USERNAME': 'Admin', 'QBITTORRENT_PASSWORD': ' Qbt-Pass ',
        })
        self.assertEqual((cfg.pia_username, cfg.pia_password), ('p1', ' Pia&Pass\\1 '))
        self.assertEqual((cfg.qbt_username, cfg.qbt_password), ('Admin', ' Qbt-Pass '))

    def setUpFiles(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.ca = str(Path(tmp.name) / 'ca.crt')
        Path(self.ca).write_text('x')

    def test_admin_username_is_allowed(self):
        with self.assertRaises(sync.ConfigError) as cm:
            sync.Config.from_env({'QBITTORRENT_USERNAME': 'admin', 'QBITTORRENT_PASSWORD': 'strongpw'})
        self.assertNotIn('QBITTORRENT_USERNAME', ' '.join(cm.exception.errors))


if __name__ == '__main__':
    unittest.main()
