#!/usr/bin/env python3
"""
Regression tests: root must never follow tenant-controlled symlinks.

The service runs as root while /var/www/<uuid> belongs to the website user.
These tests build a fake /var/www in a temporary directory, plant symlinks,
FIFOs and hard links the way a hostile tenant would, and check that files
outside the webspace ("victims") are never written, chowned or chmodded.

They run unprivileged (chown to your own uid is allowed), so the attack shows
up as a changed mode or content on the victim. Run with:

    python3 -m unittest discover -s tests -v
"""

import errno
import importlib.machinery
import importlib.util
import logging
import os
import stat
import tempfile
import threading
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Every temporary tree a test creates is removed when the run ends (tests make
# directories unreadable, plant FIFOs and links, so restore permissions first).
import atexit
import shutil
_made_tmp = []
_real_mkdtemp = tempfile.mkdtemp


def _mkdtemp(*a, **kw):
    d = _real_mkdtemp(*a, **kw)
    _made_tmp.append(d)
    return d


def _remove_tmp():
    for d in _made_tmp:
        for dirpath, dirnames, _files in os.walk(d, followlinks=False):
            for n in dirnames:
                try:
                    os.chmod(os.path.join(dirpath, n), 0o700, follow_symlinks=False)
                except (OSError, NotImplementedError):
                    pass
        shutil.rmtree(d, ignore_errors=True)


tempfile.mkdtemp = _mkdtemp
atexit.register(_remove_tmp)
UUID = "11111111-2222-3333-4444-555555555555"
# When the suite runs as root (like the service), the fake webspace is given to an
# unprivileged "tenant" uid, so ownership changes on victims are detected too.
AS_ROOT = os.geteuid() == 0
TENANT  = 65534 if AS_ROOT else os.geteuid()


def give_to_tenant(path):
    if AS_ROOT:
        for dirpath, dirnames, filenames in os.walk(path):
            os.lchown(dirpath, TENANT, TENANT)
            for n in dirnames + filenames:
                os.lchown(os.path.join(dirpath, n), TENANT, TENANT)


def load(name):
    loader = importlib.machinery.SourceFileLoader(name, str(REPO / "modules" / name))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


fcc = load("fastcgiclear")
nc  = load("nginxconf")
ngx = load("nginxtune")
LOG = logging.getLogger("test")
LOG.addHandler(logging.NullHandler())


class Victims:
    """Files and dirs outside the fake webspace that must stay untouched."""

    def __init__(self, root):
        self.root = root / "outside"
        self.root.mkdir()
        self.file = self.root / "victim.txt"
        self.file.write_text("secret\n")
        os.chmod(self.file, 0o600)
        self.dir = self.root / "victimdir"
        self.dir.mkdir()
        os.chmod(self.dir, 0o700)
        self.uids = (os.lstat(self.file).st_uid, os.lstat(self.dir).st_uid)

    def assert_untouched(self, tc):
        tc.assertEqual(self.file.read_text(), "secret\n")
        tc.assertEqual(stat.S_IMODE(os.lstat(self.file).st_mode), 0o600)
        tc.assertEqual(stat.S_IMODE(os.lstat(self.dir).st_mode), 0o700)
        tc.assertEqual(os.listdir(self.dir), [])
        tc.assertEqual((os.lstat(self.file).st_uid, os.lstat(self.dir).st_uid), self.uids)


class FastcgiclearTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.www = self.tmp / "www"
        self.www.mkdir()
        # like production: /var/www is 0711, so the site user can reach its webspace
        os.chmod(self.tmp, 0o711)
        os.chmod(self.www, 0o711)
        fcc.WWW_DIR = self.www
        self.ws = self.www / UUID
        self.ws.mkdir()
        give_to_tenant(self.ws)
        self.v = Victims(self.tmp)
        # nginx.conf loading the vhosts the way Enhance's does
        (self.tmp / "nginx.conf").write_text(f"http {{ include {self.tmp}/sites-enabled/*; }}\n")
        fcc.NGINX_CONF = self.tmp / "nginx.conf"
        fcc.NGINX_CONF_DIR = self.tmp

    def wp(self, *sub):
        root = self.ws.joinpath(*sub)
        (root / "wp-content").mkdir(parents=True)
        (root / "wp-config.php").write_text("<?php\n")
        give_to_tenant(self.ws)
        return root

    # --- clear.cache -------------------------------------------------------

    def test_flag_created_normally(self):
        fcc.ensure_flag_file(UUID)
        f = self.ws / "clear.cache"
        self.assertTrue(f.is_file() and not f.is_symlink())
        self.assertEqual(f.read_text(), "cache=cleared\n")
        self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o644)
        self.assertEqual(fcc.read_flag(UUID), "cache=cleared")

    def test_flag_symlink_refused_by_ensure(self):
        (self.ws / "clear.cache").symlink_to(self.v.file)
        with self.assertRaises(fcc.UnsafePath):
            fcc.ensure_flag_file(UUID)
        self.v.assert_untouched(self)

    def test_flag_symlink_refused_by_reset(self):
        (self.ws / "clear.cache").symlink_to(self.v.file)
        with self.assertRaises(fcc.UnsafePath):
            fcc.write_flag_cleared(UUID)
        self.v.assert_untouched(self)

    def test_flag_symlink_not_read(self):
        (self.ws / "clear.cache").symlink_to(self.v.file)
        with self.assertRaises(fcc.UnsafePath):
            fcc.read_flag(UUID)

    def test_flag_dangling_symlink_not_created(self):
        target = self.v.root / "created-by-root"
        (self.ws / "clear.cache").symlink_to(target)
        with self.assertRaises(fcc.UnsafePath):
            fcc.write_flag_cleared(UUID)
        self.assertFalse(target.exists())

    def test_flag_fifo_does_not_block(self):
        os.mkfifo(self.ws / "clear.cache")
        done = {}

        def run():
            try:
                fcc.read_flag(UUID)
            except fcc.UnsafePath:
                done["refused"] = True
        t = threading.Thread(target=run, daemon=True)
        t.start()
        t.join(3)
        self.assertFalse(t.is_alive(), "read_flag blocked on a FIFO")
        self.assertTrue(done.get("refused"))

    def test_flag_hardlink_refused(self):
        os.link(self.v.file, self.ws / "clear.cache")
        with self.assertRaises(fcc.UnsafePath):
            fcc.write_flag_cleared(UUID)
        self.v.assert_untouched(self)

    def test_webspace_itself_symlink_refused(self):
        other = "99999999-2222-3333-4444-555555555555"
        (self.www / other).symlink_to(self.v.dir)
        with self.assertRaises(fcc.UnsafePath):
            fcc.ensure_flag_file(other)
        self.v.assert_untouched(self)

    def test_bad_uuid_refused(self):
        for name in ("../etc", "", "x/y", UUID + "/.."):
            with self.assertRaises(fcc.UnsafePath):
                fcc.open_webspace(name)

    # --- mu-plugin deployment ----------------------------------------------

    def test_mu_plugin_deployed_root_and_subdir(self):
        self.wp("public_html")
        self.wp("public_html", "blog")
        res, note = fcc.deploy_mu_plugin(UUID, b"<?php // plugin\n")
        self.assertIsNone(note)
        self.assertEqual(len(res), 2)
        self.assertTrue(all(ok for _, ok, _ in res), res)
        for p in ("public_html", "public_html/blog"):
            f = self.ws / p / "wp-content/mu-plugins/fastcgiclear.php"
            self.assertEqual(f.read_bytes(), b"<?php // plugin\n")
            self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o644)
            self.assertEqual(f.stat().st_uid, TENANT)
            self.assertEqual(f.parent.stat().st_uid, TENANT)
        # idempotent
        res, _ = fcc.deploy_mu_plugin(UUID, b"<?php // plugin\n")
        self.assertTrue(all(ok for _, ok, _ in res), res)

    def test_mu_plugins_dir_symlink_refused(self):
        root = self.wp("public_html")
        (root / "wp-content/mu-plugins").symlink_to(self.v.dir)
        res, _ = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertEqual(len(res), 1)
        self.assertFalse(res[0][1])
        self.v.assert_untouched(self)

    def test_mu_plugin_file_symlink_refused(self):
        root = self.wp("public_html")
        (root / "wp-content/mu-plugins").mkdir()
        (root / "wp-content/mu-plugins/fastcgiclear.php").symlink_to(self.v.file)
        res, _ = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertFalse(res[0][1])
        self.v.assert_untouched(self)

    def test_wp_content_symlink_refused(self):
        root = self.ws / "public_html"
        root.mkdir()
        (root / "wp-config.php").write_text("<?php\n")
        (root / "wp-content").symlink_to(self.v.dir)
        res, _ = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertTrue(all(not ok for _, ok, _ in res))
        self.v.assert_untouched(self)

    def test_symlinked_directory_not_walked(self):
        # a symlinked dir that looks like a WordPress root must not be found
        fake = self.v.root / "fakewp"
        (fake / "wp-content").mkdir(parents=True)
        (fake / "wp-config.php").write_text("<?php\n")
        os.chmod(fake / "wp-content", 0o700)
        (self.ws / "public_html").symlink_to(fake)
        res, _ = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertEqual(res, [])
        self.assertFalse((fake / "wp-content/mu-plugins").exists())

    def test_mu_plugin_hardlink_refused(self):
        root = self.wp("public_html")
        (root / "wp-content/mu-plugins").mkdir()
        os.link(self.v.file, root / "wp-content/mu-plugins/fastcgiclear.php")
        res, _ = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertFalse(res[0][1])
        self.v.assert_untouched(self)


    # --- ownership: never hand over something we did not create ------------

    @unittest.skipUnless(AS_ROOT, "needs root to own files as another uid")
    def test_flag_root_owned_refused(self):
        f = self.ws / "clear.cache"
        f.write_text("x\n")
        os.chmod(f, 0o600)
        with self.assertRaises(fcc.UnsafePath):
            fcc.ensure_flag_file(UUID)
        with self.assertRaises(fcc.UnsafePath):
            fcc.write_flag_cleared(UUID)
        st = os.lstat(f)
        self.assertEqual((st.st_uid, stat.S_IMODE(st.st_mode), f.read_text()), (0, 0o600, "x\n"))

    @unittest.skipUnless(AS_ROOT, "needs root to own files as another uid")
    def test_flag_created_owned_by_tenant(self):
        fcc.ensure_flag_file(UUID)
        self.assertEqual(os.lstat(self.ws / "clear.cache").st_uid, TENANT)

    @unittest.skipUnless(AS_ROOT, "needs root to own files as another uid")
    def test_mu_dir_root_owned_refused(self):
        root = self.wp("public_html")
        mu = root / "wp-content/mu-plugins"
        mu.mkdir()
        os.chmod(mu, 0o700)       # root-owned, e.g. a directory the tenant moved into place
        res, _ = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertFalse(res[0][1])
        st = os.lstat(mu)
        self.assertEqual((st.st_uid, stat.S_IMODE(st.st_mode)), (0, 0o700))
        self.assertEqual(os.listdir(mu), [])

    @unittest.skipUnless(AS_ROOT, "needs root to own files as another uid")
    def test_mu_file_root_owned_refused(self):
        root = self.wp("public_html")
        mu = root / "wp-content/mu-plugins"
        mu.mkdir()
        os.lchown(mu, TENANT, TENANT)
        f = mu / "fastcgiclear.php"
        f.write_text("root\n")
        os.chmod(f, 0o600)
        res, _ = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertFalse(res[0][1])
        self.assertEqual((os.lstat(f).st_uid, f.read_text()), (0, "root\n"))

    # --- bounded search ----------------------------------------------------

    def _with(self, **kw):
        old = {k: getattr(fcc, k) for k in kw}
        for k, v in kw.items():
            setattr(fcc, k, v)
        self.addCleanup(lambda: [setattr(fcc, k, v) for k, v in old.items()])

    def test_walk_depth_limit(self):
        self.wp("a", "b", "c")
        self._with(WALK_MAX_DEPTH=2)
        res, _ = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertEqual(res, [])
        self._with(WALK_MAX_DEPTH=3)
        res, _ = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertEqual([r[0] for r in res], ["a/b/c/wp-content/mu-plugins/fastcgiclear.php"])

    def test_walk_roots_and_dirs_limits(self):
        self.wp("s1")
        self.wp("s2")
        self._with(WALK_MAX_ROOTS=1)
        res, note = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertEqual(len(res), 1)
        self.assertIn("roots", note)
        self._with(WALK_MAX_ROOTS=50, WALK_MAX_DIRS=2)
        res, note = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertIn("directories", note)

    def test_walk_skips_wp_content_and_files_named_like_dirs(self):
        root = self.wp("public_html")
        # a nested "WordPress" inside wp-content must not be treated as a root
        (root / "wp-content/plugins/x/wp-content").mkdir(parents=True)
        (root / "wp-content/plugins/x/wp-config.php").write_text("")
        # wp-content as a regular file is not a root either
        (self.ws / "other").mkdir()
        (self.ws / "other/wp-config.php").write_text("")
        (self.ws / "other/wp-content").write_text("")
        give_to_tenant(self.ws)
        res, _ = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertEqual([r[0] for r in res], ["public_html/wp-content/mu-plugins/fastcgiclear.php"])

    # --- cache directories -------------------------------------------------

    def test_cache_dir_trust(self):
        croot = self.tmp / "nginx_cache"
        croot.mkdir()
        os.chmod(croot, 0o755)
        self._with(TRUSTED_CACHE_ROOT=croot)
        (croot / "example.com").mkdir()
        (croot / "link.com").symlink_to(self.v.dir)
        (croot / "deep").mkdir()
        (croot / "deep" / "x").mkdir()
        self.assertTrue(fcc.cache_dir_is_trusted(croot / "example.com"))
        self.assertFalse(fcc.cache_dir_is_trusted(croot / "link.com"))
        self.assertFalse(fcc.cache_dir_is_trusted(croot / "deep" / "x"))
        self.assertFalse(fcc.cache_dir_is_trusted(croot / "missing"))
        self.assertFalse(fcc.cache_dir_is_trusted(self.v.dir))
        self.assertFalse(fcc.cache_dir_is_trusted(croot / ".." / "outside"))
        self.assertFalse(fcc.cache_dir_is_trusted(croot))
        os.chmod(croot, 0o777)
        self.assertFalse(fcc.cache_dir_is_trusted(croot / "example.com"))
        os.chmod(croot, 0o755)


    def test_walk_is_breadth_first(self):
        # huge trees sorting before and after public_html must not hide it,
        # whichever end a depth-first search would start from
        for big in ("aaa-backups", "zzz-backups"):
            for i in range(30):
                (self.ws / big / f"d{i}" / "x").mkdir(parents=True)
        self.wp("public_html")
        self._with(WALK_MAX_DIRS=10)
        res, note = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertEqual([r[0] for r in res], ["public_html/wp-content/mu-plugins/fastcgiclear.php"])

    def test_wp_content_found_in_a_wide_directory(self):
        root = self.wp("public_html")
        for i in range(12):
            (root / f"a{i:02d}").mkdir()
        give_to_tenant(self.ws)
        self._with(WALK_MAX_DIRS=5)
        res, _ = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertEqual([r[0] for r in res], ["public_html/wp-content/mu-plugins/fastcgiclear.php"])

    def test_walk_entry_limit(self):
        for i in range(5):
            (self.ws / f"d{i}").mkdir()
        give_to_tenant(self.ws)
        self._with(WALK_MAX_ENTRIES=3)
        res, note = fcc.deploy_mu_plugin(UUID, b"<?php\n")
        self.assertIn("entries", note)

    def test_mkdir_as_other_user_refused_unprivileged(self):
        if AS_ROOT:
            self.skipTest("unprivileged only")
        fd = os.open(self.ws, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaises(fcc.UnsafePath):
                fcc._mkdir_as(fd, "x", os.geteuid() + 1)
            with self.assertRaises(fcc.UnsafePath):
                fcc._mkdir_as(fd, "../x", os.geteuid())
            with self.assertRaises(fcc.UnsafePath):
                fcc._mkdir_as(fd, "x", 0)
        finally:
            os.close(fd)
        self.assertFalse((self.ws / "x").exists())

    def test_mkdir_as_creates_inside_fd_as_site_user(self):
        import pwd
        sub = self.ws / "sub"
        sub.mkdir()
        give_to_tenant(self.ws)
        fd = os.open(sub, os.O_RDONLY | os.O_DIRECTORY)
        try:
            # the fd stays bound to the original directory even if the path is swapped
            os.rename(sub, self.ws / "moved")
            (self.ws / "sub").symlink_to(self.v.dir)
            fcc._mkdir_as(fd, "made", TENANT)
            fcc._mkdir_as(fd, "made", TENANT)          # exists: fine
        finally:
            os.close(fd)
        st = os.lstat(self.ws / "moved" / "made")
        self.assertEqual(st.st_uid, TENANT)
        if AS_ROOT:
            self.assertEqual(st.st_gid, pwd.getpwuid(TENANT).pw_gid)
        self.v.assert_untouched(self)

    def test_find_cache_paths_matches_enhance_log_only(self):
        sites = self.tmp / "sites-enabled"
        sites.mkdir()
        self._with(SITES_DIR=sites)
        other = "99999999-2222-3333-4444-555555555555"
        (sites / "a.conf").write_text(
            "fastcgi_cache_path /c/a levels=1:2 keys_zone=a:10m;\n"
            f"server {{ access_log /var/local/enhance/webserver_logs/{UUID}.log a; }}\n")
        (sites / "a-preview.conf").write_text(
            "fastcgi_cache_path /c/ap levels=1:2 keys_zone=ap:10m;\n"
            f"server {{ access_log /var/local/enhance/webserver_logs/{UUID}.log ap; }}\n")
        (sites / "b.conf").write_text(
            f"# moved from {UUID}\nroot /var/www/{UUID}/x;\n"
            "fastcgi_cache_path /c/b levels=1:2 keys_zone=b:10m;\n"
            f"server {{ access_log /var/local/enhance/webserver_logs/{other}.log b; }}\n")
        self.assertEqual(sorted(map(str, fcc.find_cache_paths(UUID))), ["/c/a", "/c/ap"])
        # a vhost removed while scanning (here: dangling) makes the list unreliable
        (sites / "gone.conf").symlink_to(sites / "does-not-exist.conf")
        with self.assertRaises(fcc.UnsafePath):
            fcc.find_cache_paths(UUID)
        os.unlink(sites / "gone.conf")
        # two cache zones on one line are two directives
        (sites / "a.conf").write_text(
            "fastcgi_cache_path /c/a keys_zone=a:1m; fastcgi_cache_path /c/z keys_zone=z:1m;\n"
            f"server {{ access_log /var/local/enhance/webserver_logs/{UUID}.log a; }}\n")
        with self.assertRaises(fcc.UnsafePath):
            fcc.find_cache_paths(UUID)
        (sites / "a.conf").write_text(
            "fastcgi_cache_path /c/a levels=1:2 keys_zone=a:10m;\n"
            f"server {{ access_log /var/local/enhance/webserver_logs/{UUID}.log a; }}\n")
        (sites / "a-preview.conf").write_text(
            "fastcgi_cache_path \"/c/a p\" levels=1:2 keys_zone=ap:10m;\n"
            f"server {{ access_log /var/local/enhance/webserver_logs/{UUID}.log ap; }}\n")
        self.assertEqual(sorted(map(str, fcc.find_cache_paths(UUID))), ["/c/a", "/c/a p"])
        # an alias vhost of the same webspace with caching off has no cache zone
        (sites / "alias.conf").write_text(
            f"server {{ access_log /var/local/enhance/webserver_logs/{UUID}.log al; }}\n")
        self.assertEqual(sorted(map(str, fcc.find_cache_paths(UUID))), ["/c/a", "/c/a p"])
        # a vhost of the webspace that cannot be parsed makes the list unreliable
        (sites / "alias.conf").write_text(
            "fastcgi_cache_path \"/c/al x levels=1:2;\n"
            f"server {{ access_log /var/local/enhance/webserver_logs/{UUID}.log al; }}\n")
        with self.assertRaises(fcc.UnsafePath):
            fcc.find_cache_paths(UUID)
        # directive text inside an argument or a comment is not a directive
        (sites / "alias.conf").write_text(
            "add_header X-Doc \"fastcgi_cache_path /c/evil levels=1:2 keys_zone=c_evil_1:1m;\";\n"
            "# fastcgi_cache_path /c/old levels=1:2 keys_zone=c_old_2:1m;\n"
            f"server {{ access_log /var/local/enhance/webserver_logs/{UUID}.log al; }}\n")
        self.assertEqual(sorted(map(str, fcc.find_cache_paths(UUID))), ["/c/a", "/c/a p"])
        # a vhost that mentions the webspace's log only in a comment is not the webspace's
        (sites / "alias.conf").write_text(
            "fastcgi_cache_path /c/other levels=1:2 keys_zone=c_other_3:1m;\n"
            f"# access_log /var/local/enhance/webserver_logs/{UUID}.log al;\n"
            "server { access_log /var/local/enhance/webserver_logs/99999999-2222-3333-4444-555555555555.log o; }\n")
        self.assertEqual(sorted(map(str, fcc.find_cache_paths(UUID))), ["/c/a", "/c/a p"])
        # rows of a map block are data, not cache zones
        (sites / "alias.conf").write_text(
            "map $a $b { fastcgi_cache_path /c/evil; }\n"
            f"server {{ access_log /var/local/enhance/webserver_logs/{UUID}.log al; }}\n")
        self.assertEqual(sorted(map(str, fcc.find_cache_paths(UUID))), ["/c/a", "/c/a p"])
        # the webspace log outside a server block, or from an included file,
        # could hide a vhost with its own cache zone: refuse
        (sites / "alias.conf").write_text(
            "fastcgi_cache_path /c/hidden levels=1:2 keys_zone=c_hidden_4:1m;\n"
            f"access_log /var/local/enhance/webserver_logs/{UUID}.log al;\nserver {{ listen 80; }}\n")
        with self.assertRaises(fcc.UnsafePath):
            fcc.find_cache_paths(UUID)
        inc = self.tmp / "inc.conf"
        inc.write_text(f"access_log /var/local/enhance/webserver_logs/{UUID}.log al;\n")
        (sites / "alias.conf").write_text(
            "fastcgi_cache_path /c/hidden levels=1:2 keys_zone=c_hidden_5:1m;\n"
            f"server {{ include {inc}; }}\n")
        with self.assertRaises(fcc.UnsafePath):
            fcc.find_cache_paths(UUID)
        os.unlink(sites / "alias.conf")
        # an include that disappears (or is not a regular file) makes the whole
        # answer unreliable, even for a vhost that does not name the webspace
        (sites / "alias.conf").write_text(
            "fastcgi_cache_path /c/hidden levels=1:2 keys_zone=c_hidden_6:1m;\n"
            f"server {{ include {self.tmp}/gone.conf; }}\n")
        with self.assertRaises(fcc.UnsafePath):
            fcc.find_cache_paths(UUID)
        fifo = self.tmp / "fifo.conf"
        os.mkfifo(fifo)
        (sites / "alias.conf").write_text(f"server {{ include {fifo}; }}\n")
        done = {}

        def scan():
            try:
                fcc.find_cache_paths(UUID)
            except fcc.UnsafePath:
                done["refused"] = True
        t = threading.Thread(target=scan, daemon=True)
        t.start()
        t.join(3)
        self.assertFalse(t.is_alive(), "include of a FIFO blocked the scan")
        self.assertTrue(done.get("refused"))
        os.unlink(sites / "alias.conf")
        # the webspace log inherited from nginx.conf's http block, or set in a
        # location, is not a vhost's own server-level log: refuse
        (self.tmp / "nginx.conf").write_text(
            f"http {{ access_log /var/local/enhance/webserver_logs/{UUID}.log m;\n"
            f"include {self.tmp}/sites-enabled/*; }}\n")
        with self.assertRaises(fcc.UnsafePath):
            fcc.find_cache_paths(UUID)
        (self.tmp / "nginx.conf").write_text(f"http {{ include {self.tmp}/sites-enabled/*; }}\n")
        (sites / "alias.conf").write_text(
            f"server {{ location / {{ access_log /var/local/enhance/webserver_logs/{UUID}.log al; }} }}\n")
        with self.assertRaises(fcc.UnsafePath):
            fcc.find_cache_paths(UUID)
        # a map row in an included file is data, not a log
        inc = self.tmp / "maps.conf"
        inc.write_text(f"map $a $b {{ access_log /var/local/enhance/webserver_logs/{UUID}.log; }}\n")
        (sites / "alias.conf").write_text(f"include {inc};\n")
        self.assertEqual(sorted(map(str, fcc.find_cache_paths(UUID))), ["/c/a", "/c/a p"])
        # a log fragment in sites-enabled, included into an alias's server block,
        # is not a vhost of its own: refuse instead of missing the alias cache
        # (nginx.conf loads only *.conf here, so the fragment is only seen inside
        # the server block)
        (self.tmp / "nginx.conf").write_text(f"http {{ include {sites}/*.conf; }}\n")
        (sites / "alias.conf").write_text(
            "fastcgi_cache_path /c/hidden levels=1:2 keys_zone=c_hidden_7:1m;\n"
            f"server {{ include {sites}/alias-log.inc; }}\n")
        (sites / "alias-log.inc").write_text(
            f"access_log /var/local/enhance/webserver_logs/{UUID}.log al;\n")
        with self.assertRaises(fcc.UnsafePath):
            fcc.find_cache_paths(UUID)
        os.unlink(sites / "alias-log.inc")
        (self.tmp / "nginx.conf").write_text(f"http {{ include {self.tmp}/sites-enabled/*; }}\n")
        # a vhost file on disk that names the webspace but is not loaded (an
        # include edited, not reloaded yet) may still be served: refuse
        (self.tmp / "nginx.conf").write_text(f"http {{ include {sites}/a*.conf; }}\n")
        (sites / "alias.conf").write_text(
            "fastcgi_cache_path /c/other levels=1:2 keys_zone=c_other_8:1m;\n"
            f"server {{ access_log /var/local/enhance/webserver_logs/{UUID}.log al; }}\n")
        (sites / "b-pending.conf").write_text(
            "fastcgi_cache_path /c/pending levels=1:2 keys_zone=c_pending_9:1m;\n"
            f"server {{ access_log /var/local/enhance/webserver_logs/{UUID}.log p; }}\n")
        with self.assertRaises(fcc.UnsafePath):
            fcc.find_cache_paths(UUID)
        os.unlink(sites / "b-pending.conf")
        os.unlink(sites / "alias.conf")
        (self.tmp / "nginx.conf").write_text(f"http {{ include {self.tmp}/sites-enabled/*; }}\n")
        # a path that only looks like sites-enabled after collapsing '..' is not
        jumpdst = self.tmp / "elsewhere" / "nested"
        jumpdst.mkdir(parents=True)
        (self.tmp / "elsewhere" / "sites-enabled").mkdir()
        (self.tmp / "elsewhere" / "sites-enabled" / "x.conf").write_text(
            "fastcgi_cache_path /c/outside levels=1:2 keys_zone=c_outside_10:1m;\n"
            f"server {{ access_log /var/local/enhance/webserver_logs/{UUID}.log x; }}\n")
        (self.tmp / "jump").symlink_to(jumpdst)
        (self.tmp / "nginx.conf").write_text(
            f"http {{ include {self.tmp}/sites-enabled/*; include {self.tmp}/jump/../sites-enabled/x.conf; }}\n")
        with self.assertRaises(fcc.UnsafePath):
            fcc.find_cache_paths(UUID)
        (self.tmp / "nginx.conf").write_text(f"http {{ include {self.tmp}/sites-enabled/*; }}\n")
        # a pending vhost whose log comes from an include outside sites-enabled
        (self.tmp / "nginx.conf").write_text(f"http {{ include {sites}/a*.conf; }}\n")
        frag = self.tmp / "frag.inc"
        frag.write_text(f"access_log /var/local/enhance/webserver_logs/{UUID}.log f;\n")
        (sites / "b-pending.conf").write_text(
            f"fastcgi_cache_path /c/pending levels=1:2 keys_zone=c_pending_11:1m;\nserver {{ include {frag}; }}\n")
        with self.assertRaises(fcc.UnsafePath):
            fcc.find_cache_paths(UUID)
        os.unlink(sites / "b-pending.conf")
        (self.tmp / "nginx.conf").write_text(f"http {{ include {self.tmp}/sites-enabled/*; }}\n")
        # editor files, .git and sub-directories in sites-enabled do not block
        (sites / ".git").mkdir()
        (sites / ".#a.conf").symlink_to(self.tmp / "nowhere")
        (sites / ".a.conf.swp").write_bytes(
            b"\x00\x01 access_log /var/local/enhance/webserver_logs/" + UUID.encode() + b".log x; {")
        (sites / "disabled").mkdir()
        (self.tmp / "nginx.conf").write_text(f"http {{ include {sites}/*.conf; }}\n")
        self.assertEqual(sorted(map(str, fcc.find_cache_paths(UUID))), ["/c/a", "/c/a p"])
        (self.tmp / "nginx.conf").write_text(f"http {{ include {self.tmp}/sites-enabled/*; }}\n")
        for n in (".#a.conf", ".a.conf.swp"):
            os.unlink(sites / n)
        os.rmdir(sites / ".git")
        os.rmdir(sites / "disabled")
        # sites-enabled entries may be symlinks into sites-available
        avail = self.tmp / "sites-available"
        avail.mkdir()
        (avail / "linked.conf").write_text(
            "fastcgi_cache_path /c/linked levels=1:2 keys_zone=c_linked_12:1m;\n"
            f"server {{ access_log /var/local/enhance/webserver_logs/{UUID}.log l; }}\n")
        (sites / "linked.conf").symlink_to(avail / "linked.conf")
        self.assertEqual(sorted(map(str, fcc.find_cache_paths(UUID))), ["/c/a", "/c/a p", "/c/linked"])
        os.unlink(sites / "linked.conf")
        # a zone must belong to one vhost: used elsewhere, or a vhost using a
        # zone declared elsewhere, makes the purge ambiguous
        (sites / "zz-other.conf").write_text("server { location / { fastcgi_cache a; } }\n")
        with self.assertRaises(fcc.UnsafePath):
            fcc.find_cache_paths(UUID)
        os.unlink(sites / "zz-other.conf")
        (sites / "alias.conf").write_text(
            f"server {{ access_log /var/local/enhance/webserver_logs/{UUID}.log al; fastcgi_cache a; }}\n")
        with self.assertRaises(fcc.UnsafePath):
            fcc.find_cache_paths(UUID)
        # ... also through a location include inside the alias's server block
        (sites / "zz-other.conf").write_text(
            "fastcgi_cache_path /c/foreign levels=1:2 keys_zone=foreign:1m;\n"
            "server { access_log /var/local/enhance/webserver_logs/99999999-2222-3333-4444-555555555555.log o; }\n")
        loc = self.tmp / "loc.inc"
        loc.write_text("fastcgi_cache foreign;\n")
        (sites / "alias.conf").write_text(
            f"server {{ access_log /var/local/enhance/webserver_logs/{UUID}.log al; location / {{ include {loc}; }} }}\n")
        with self.assertRaises(fcc.UnsafePath):
            fcc.find_cache_paths(UUID)
        os.unlink(sites / "zz-other.conf")
        # two sites grouped in one vhost file: its zone may serve both
        (sites / "alias.conf").write_text(
            "fastcgi_cache_path /c/both levels=1:2 keys_zone=both:1m;\n"
            f"server {{ access_log /var/local/enhance/webserver_logs/{UUID}.log al; fastcgi_cache both; }}\n"
            "server { access_log /var/local/enhance/webserver_logs/99999999-2222-3333-4444-555555555555.log o; fastcgi_cache both; }\n")
        with self.assertRaises(fcc.UnsafePath):
            fcc.find_cache_paths(UUID)
        # a vhost_includes-style file using the vhost's own zone is fine
        os.unlink(sites / "alias.conf")
        own = self.tmp / "own.inc"
        own.write_text("fastcgi_cache a;\n")
        (sites / "a.conf").write_text(
            "fastcgi_cache_path /c/a levels=1:2 keys_zone=a:10m;\n"
            f"server {{ access_log /var/local/enhance/webserver_logs/{UUID}.log a; include {own}; }}\n")
        self.assertEqual(sorted(map(str, fcc.find_cache_paths(UUID))), ["/c/a", "/c/a p"])
        # a zone set at http level in nginx.conf is inherited by every site
        (self.tmp / "nginx.conf").write_text(
            f"http {{ fastcgi_cache shared; include {self.tmp}/sites-enabled/*; }}\n")
        with self.assertRaises(fcc.UnsafePath):
            fcc.find_cache_paths(UUID)
        (self.tmp / "nginx.conf").write_text(f"http {{ include {self.tmp}/sites-enabled/*; }}\n")
        # ... also a zone of an unrelated site
        (sites / "zz-other.conf").write_text(
            "fastcgi_cache_path /c/foreign levels=1:2 keys_zone=foreign:1m;\n"
            "server { access_log /var/local/enhance/webserver_logs/99999999-2222-3333-4444-555555555555.log o; }\n")
        (sites / "alias.conf").write_text(
            f"server {{ access_log /var/local/enhance/webserver_logs/{UUID}.log al; fastcgi_cache foreign; }}\n")
        with self.assertRaises(fcc.UnsafePath):
            fcc.find_cache_paths(UUID)
        os.unlink(sites / "zz-other.conf")
        (sites / "alias.conf").write_text(
            f"server {{ access_log /var/local/enhance/webserver_logs/{UUID}.log al; fastcgi_cache off; }}\n")
        self.assertEqual(sorted(map(str, fcc.find_cache_paths(UUID))), ["/c/a", "/c/a p"])
        os.unlink(sites / "alias.conf")
        # a top-level include in a matched vhost could declare more zones
        zones = self.tmp / "zones.conf"
        zones.write_text("fastcgi_cache_path /c/zone levels=1:2 keys_zone=c_zone_13:1m;\n")
        (sites / "alias.conf").write_text(
            f"include {zones};\n"
            f"server {{ access_log /var/local/enhance/webserver_logs/{UUID}.log al; }}\n")
        with self.assertRaises(fcc.UnsafePath):
            fcc.find_cache_paths(UUID)
        os.unlink(sites / "alias.conf")
        (sites / "two.conf").write_text(
            "fastcgi_cache_path /c/x levels=1:2 keys_zone=x:10m;\n"
            "fastcgi_cache_path /c/y levels=1:2 keys_zone=y:10m;\n"
            f"server {{ access_log /var/local/enhance/webserver_logs/{UUID}.log x; }}\n")
        with self.assertRaises(fcc.UnsafePath):
            fcc.find_cache_paths(UUID)

    def test_find_cache_paths_needs_a_vhost(self):
        sites = self.tmp / "sites-enabled"
        self._with(SITES_DIR=sites)
        with self.assertRaises(fcc.UnsafePath):        # missing directory
            fcc.find_cache_paths(UUID)
        sites.mkdir()
        with self.assertRaises(fcc.UnsafePath):        # no vhost names the webspace
            fcc.find_cache_paths(UUID)
        (sites / "x.conf").write_text(
            "server { access_log /var/local/enhance/webserver_logs/99999999-2222-3333-4444-555555555555.log x; }\n")
        with self.assertRaises(fcc.UnsafePath):
            fcc.find_cache_paths(UUID)

    def test_clear_cache_dir_empties_without_following_links(self):
        c = self.tmp / "cache"
        (c / "1" / "ab").mkdir(parents=True)
        (c / "1" / "ab" / "key").write_text("x")
        (c / "f").write_text("x")
        (c / "link").symlink_to(self.v.dir)
        (c / "1" / "dlink").symlink_to(self.v.dir)
        self.assertEqual(fcc.clear_cache_dir(c), [])
        self.assertEqual(os.listdir(c), [])
        self.v.assert_untouched(self)

    def test_clear_cache_dir_vanished_entries_are_not_errors(self):
        # nginx's cache manager can expire entries while we delete; simulate the
        # error rmtree reports then, and a real failure for comparison
        c = self.tmp / "cache"
        (c / "1" / "ab").mkdir(parents=True)
        real = fcc.shutil.rmtree

        def fake(exc_type):
            def rmtree(path, onexc=None, onerror=None):
                if os.path.lexists(path):
                    real(path)
                exc = exc_type(2, "simulated", path)
                if onexc:
                    onexc(os.unlink, path, exc)
                else:
                    onerror(os.unlink, path, (type(exc), exc, None))
            return rmtree
        try:
            fcc.shutil.rmtree = fake(FileNotFoundError)
            self.assertEqual(fcc.clear_cache_dir(c), [])
            # a response cached into a hash dir during the clear may be stale: error
            (c / "3").mkdir()
            fcc.shutil.rmtree = fake(lambda e, m, p: OSError(errno.ENOTEMPTY, m, p))
            self.assertEqual(len(fcc.clear_cache_dir(c)), 1)
            (c / "2").mkdir()
            fcc.shutil.rmtree = fake(PermissionError)
            self.assertEqual(len(fcc.clear_cache_dir(c)), 1)
        finally:
            fcc.shutil.rmtree = real

    def test_clear_site_cache(self):
        sites = self.tmp / "sites-enabled"
        sites.mkdir()
        croot = self.tmp / "nginx_cache"
        croot.mkdir()
        os.chmod(croot, 0o755)
        self._with(SITES_DIR=sites, TRUSTED_CACHE_ROOT=croot)
        log = f"server {{ access_log /var/local/enhance/webserver_logs/{UUID}.log a; }}\n"
        (sites / "a.conf").write_text(f"fastcgi_cache_path {croot}/a.eu keys_zone=a:1m;\n" + log)
        (sites / "b.conf").write_text(f"fastcgi_cache_path {croot}/b.eu keys_zone=b:1m;\n" + log)
        (croot / "a.eu" / "1" / "aa").mkdir(parents=True)
        (croot / "a.eu" / "1" / "aa" / "k").write_text("x")
        # b.eu not created yet: nothing cached, still a complete clear
        self.assertTrue(fcc.clear_site_cache(UUID, LOG))
        self.assertEqual(os.listdir(croot / "a.eu"), [])
        # a cache path outside the trusted root is a failure, nothing deleted there
        (self.tmp / "other").mkdir()
        (self.tmp / "other" / "keep").write_text("x")
        (sites / "b.conf").write_text(f"fastcgi_cache_path {self.tmp}/other keys_zone=b:1m;\n" + log)
        self.assertFalse(fcc.clear_site_cache(UUID, LOG))
        self.assertTrue((self.tmp / "other" / "keep").exists())
        # a symlinked cache dir below the root is a failure, its target untouched
        (sites / "b.conf").write_text(f"fastcgi_cache_path {croot}/b.eu keys_zone=b:1m;\n" + log)
        (croot / "b.eu").symlink_to(self.v.dir)
        self.assertFalse(fcc.clear_site_cache(UUID, LOG))
        self.v.assert_untouched(self)

    def test_clear_cache_dir_retries_a_bucket_nginx_wrote_into(self):
        c = self.tmp / "cache"
        (c / "a" / "0f").mkdir(parents=True)
        real, calls = fcc.shutil.rmtree, []

        def rmtree(path, onexc=None, onerror=None):
            calls.append(path)
            if len(calls) == 1:          # first removal: nginx wrote a new entry meanwhile
                exc = OSError(errno.ENOTEMPTY, "simulated", path)
                (onexc(os.rmdir, path, exc) if onexc else onerror(os.rmdir, path, (OSError, exc, None)))
                return
            real(path)
        fcc.shutil.rmtree = rmtree
        try:
            self.assertEqual(fcc.clear_cache_dir(c), [])
        finally:
            fcc.shutil.rmtree = real
        self.assertEqual(len(calls), 2)
        self.assertEqual(os.listdir(c), [])

    def test_clear_site_cache_empties_every_dir_on_every_attempt(self):
        sites = self.tmp / "sites-enabled"
        sites.mkdir()
        croot = self.tmp / "nginx_cache"
        croot.mkdir()
        os.chmod(croot, 0o755)
        self._with(SITES_DIR=sites, TRUSTED_CACHE_ROOT=croot)
        (sites / "a.conf").write_text(f"fastcgi_cache_path {croot}/a.eu keys_zone=a:1m;\n"
                                      f"server {{ access_log /var/local/enhance/webserver_logs/{UUID}.log a; }}\n")
        (croot / "a.eu" / "1").mkdir(parents=True)
        self.assertTrue(fcc.clear_site_cache(UUID, LOG))
        # a directory restored at the same path (maybe with the same inode) is
        # emptied again by the next attempt
        import shutil as _sh
        _sh.rmtree(croot / "a.eu")
        (croot / "a.eu" / "old").mkdir(parents=True)
        self.assertTrue(fcc.clear_site_cache(UUID, LOG))
        self.assertEqual(os.listdir(croot / "a.eu"), [])

    def test_clear_cache_dir_reports_failures(self):
        if AS_ROOT:
            self.skipTest("root ignores permissions")
        c = self.tmp / "cache"
        (c / "locked").mkdir(parents=True)
        (c / "locked" / "f").write_text("x")
        os.chmod(c / "locked", 0o500)
        try:
            self.assertTrue(fcc.clear_cache_dir(c))
        finally:
            os.chmod(c / "locked", 0o700)


def ngx_env(tmp):
    """Point nginxtune at a temp tree; the worker user is nobody (exists everywhere)."""
    (tmp / "nginx.conf").write_text("user nobody;\nworker_processes auto;\n")
    ngx.NGINX_CONF = tmp / "nginx.conf"
    ngx._acl_done.clear()


class NginxtuneLogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        ngx_env(self.tmp)
        ngx.SITE_LOGS_DIR = self.tmp / "sites"
        self.v = Victims(self.tmp)

    def test_site_log_dir_created(self):
        self.assertTrue(ngx._ensure_site_log_dir(UUID, LOG))
        d = ngx.SITE_LOGS_DIR / UUID
        self.assertTrue(d.is_dir() and not d.is_symlink())

    def test_site_log_dir_symlink_refused(self):
        ngx.SITE_LOGS_DIR.mkdir()
        (ngx.SITE_LOGS_DIR / UUID).symlink_to(self.v.dir)
        self.assertFalse(ngx._ensure_site_log_dir(UUID, LOG))
        self.v.assert_untouched(self)

    @unittest.skipUnless(AS_ROOT, "ownership and ACLs need root")
    def test_site_log_dir_owner_mode_acl(self):
        self.assertTrue(ngx._ensure_site_log_dir(UUID, LOG))
        import subprocess
        for d in (ngx.SITE_LOGS_DIR, ngx.SITE_LOGS_DIR / UUID):
            st = os.lstat(d)
            self.assertEqual((st.st_uid, stat.S_IMODE(st.st_mode)), (0, 0o750))
            acl = subprocess.run(["getfacl", "-cp", str(d)], capture_output=True, text=True).stdout
            self.assertIn("user:nobody:--x", acl)

    def test_site_log_dir_unsafe_parent_refused(self):
        os.chmod(self.tmp, 0o777)
        try:
            self.assertFalse(ngx._ensure_site_log_dir(UUID, LOG))
            self.assertFalse(ngx.SITE_LOGS_DIR.exists())
        finally:
            os.chmod(self.tmp, 0o700)

    def test_site_log_dir_foreign_owner_refused(self):
        if not AS_ROOT:
            self.skipTest("needs root")
        ngx.SITE_LOGS_DIR.mkdir()
        os.chown(ngx.SITE_LOGS_DIR, TENANT, TENANT)
        self.assertFalse(ngx._ensure_site_log_dir(UUID, LOG))
        self.assertEqual(os.lstat(ngx.SITE_LOGS_DIR).st_uid, TENANT)

    def test_site_log_dir_bad_uuid_refused(self):
        for name in ("../../etc", "abc", "", UUID + "/x", UUID + "\n"):
            self.assertFalse(ngx._ensure_site_log_dir(name, LOG))
        self.assertFalse((self.tmp / "etc").exists())

    def test_filewatcher_refuses_symlink_and_fifo(self):
        ws = self.tmp / "ws"
        ws.mkdir()
        (ws / "php-error.log").symlink_to(self.v.file)
        fw = ngx.FileWatcher(str(ws / "php-error.log"), LOG, seek_to_end_on_open=False)
        self.assertIsNone(fw.fh, "opened a symlink")
        self.assertEqual(fw.readlines(), [])
        fw.close()
        os.unlink(ws / "php-error.log")
        os.mkfifo(ws / "php-error.log")
        out = {}
        t = threading.Thread(target=lambda: out.setdefault(
            "lines", ngx.FileWatcher(str(ws / "php-error.log"), LOG, False).readlines()), daemon=True)
        t.start()
        t.join(3)
        self.assertFalse(t.is_alive(), "FileWatcher blocked on a FIFO")
        self.assertEqual(out.get("lines"), [])

    def test_filewatcher_refuses_hardlink(self):
        ws = self.tmp / "ws"
        ws.mkdir()
        os.link(self.v.file, ws / "php-error.log")
        fw = ngx.FileWatcher(str(ws / "php-error.log"), LOG, seek_to_end_on_open=False)
        self.assertIsNone(fw.fh, "opened a hard link")
        self.assertEqual(fw.readlines(), [])
        fw.close()

    def test_filewatcher_reads_regular_file(self):
        f = self.tmp / "real.log"
        f.write_text("a\nb\n")
        fw = ngx.FileWatcher(str(f), LOG, seek_to_end_on_open=False)
        self.assertEqual(fw.readlines(), ["a\n", "b\n"])
        fw.close()


VHOST = """log_format example.com "\\"$remote_addr\\" \\"$msec\\"";
log_format example.com_persistent '$time_local - $remote_addr - $http_cf_ipcountry - $server_protocol - $status - $request_method - $host - $request_uri - $http_user_agent - $upstream_cache_status - $request_time - $upstream_response_time';
server {
listen 80;
server_name example.com;
access_log /var/local/enhance/webserver_logs/%(uuid)s.log example.com;
access_log /var/www/%(uuid)s/logs/webserver.log example.com_persistent;
root "/var/www/%(uuid)s/public_html";
location ~ \\.php$ {
    fastcgi_pass 127.0.0.1:9000;
}
include vhost_includes/example.com.conf;
}
""" % {"uuid": UUID}


class NginxtuneMigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        ngx_env(self.tmp)
        ngx.SITES_DIR = self.tmp / "sites-enabled"
        ngx.SITES_DIR.mkdir()
        ngx.SITE_LOGS_DIR = self.tmp / "logs"
        self.conf = ngx.SITES_DIR / "example.com.conf"
        self.conf.write_text(VHOST)

    def settle(self, cfg):
        """Apply until stable; must converge on the second pass with no change."""
        ngx.apply_logging_features(cfg, LOG)
        before = self.conf.read_text()
        self.assertFalse(ngx.apply_logging_features(cfg, LOG), "second pass changed the file")
        self.assertEqual(self.conf.read_text(), before)
        return before

    def assert_consistent(self, text):
        fmt = text.count("_persistent '")
        log = text.count("_persistent;")
        self.assertEqual(fmt, log, "persistent format and access_log out of step")
        self.assertLessEqual(fmt, 1)

    def cfg(self, pers):
        return {"general": {"persistent_logging": pers}, "nginx": {"features": {}}}

    def test_legacy_line_migrated_when_enabled(self):
        self.assertTrue(ngx.apply_logging_features(self.cfg(True), LOG))
        text = self.conf.read_text()
        self.assertNotIn("access_log /var/www/", text)
        self.assertIn(f"access_log {ngx.SITE_LOGS_DIR}/{UUID}/webserver.log example.com_persistent;", text)
        self.assertEqual(text.count("_persistent;"), 1)
        # the legacy line is removed as a whole line, not left behind as blank space
        self.assertEqual([l for l in text.splitlines() if not l.strip()], [])
        self.assertTrue((ngx.SITE_LOGS_DIR / UUID).is_dir())
        # idempotent
        self.assertFalse(ngx.apply_logging_features(self.cfg(True), LOG))

    def test_legacy_line_removed_when_disabled(self):
        self.assertTrue(ngx.apply_logging_features(self.cfg(False), LOG))
        text = self.conf.read_text()
        self.assertNotIn("access_log /var/www/", text)
        self.assertNotIn("/webserver.log", text)
        self.assertFalse(ngx.apply_logging_features(self.cfg(False), LOG))

    def test_enable_then_disable_after_migration(self):
        ngx.apply_logging_features(self.cfg(True), LOG)
        text = self.conf.read_text()
        self.assertIn("$upstream_response_time';", text)
        self.assertFalse(ngx.apply_logging_features(self.cfg(True), LOG))
        # turning everything off removes the persistent log entirely
        self.assertTrue(ngx.apply_logging_features(self.cfg(False), LOG))
        self.assertNotIn("/webserver.log", self.conf.read_text())

    def test_odd_legacy_forms_stripped(self):
        odd = VHOST.replace(
            f"access_log /var/www/{UUID}/logs/webserver.log example.com_persistent;",
            f'access_log\t"/var/www/{UUID}/logs/webserver.log"\n        example.com_persistent;\n'
            f"  access_log '/var/www/{UUID}/other.log' example.com;\n"
            f"location /x {{ access_log /var/www/{UUID}/x.log; return 204; }}")
        self.conf.write_text(odd)
        for pers in (True, False):
            text = self.settle(self.cfg(pers))
            self.assertNotRegex(text, r"access_log\s+[\"']?/var/www")
            self.assertIn("location /x {  return 204; }", text)
            self.assert_consistent(text)

    def test_vhost_without_uuid_converges_without_orphans(self):
        no_uuid = VHOST.replace(
            f"access_log /var/local/enhance/webserver_logs/{UUID}.log example.com;\n", "")
        self.conf.write_text(no_uuid)
        text = self.settle(self.cfg(True))
        self.assertNotIn("_persistent", text)
        self.assertNotIn("/var/www/" + UUID + "/logs", text)

    def test_orphan_format_removed(self):
        orphan = VHOST.replace(
            f"access_log /var/www/{UUID}/logs/webserver.log example.com_persistent;\n", "")
        self.conf.write_text(orphan)
        text = self.settle(self.cfg(False))
        self.assertNotIn("_persistent", text)

    def test_log_dir_failure_means_no_persistent_lines(self):
        ngx.SITE_LOGS_DIR.mkdir()
        (ngx.SITE_LOGS_DIR / UUID).symlink_to(self.tmp)
        text = self.settle(self.cfg(True))
        self.assertNotIn("_persistent", text)
        self.assertNotIn("/var/www/" + UUID + "/logs", text)

    def test_dotted_format_name_used_for_both_lines(self):
        text = self.settle(self.cfg(True))
        self.assertIn("log_format example.com_persistent '", text)
        self.assertIn("webserver.log example.com_persistent;", text)
        self.assert_consistent(text)

    def test_unchanged_file_not_rewritten(self):
        self.settle(self.cfg(True))
        m1 = os.stat(self.conf).st_mtime_ns
        self.assertFalse(ngx.apply_logging_features(self.cfg(True), LOG))
        self.assertEqual(os.stat(self.conf).st_mtime_ns, m1)

    def test_multiline_log_format_gets_no_persistent_lines(self):
        ml = VHOST.replace('log_format example.com "\\"$remote_addr\\" \\"$msec\\"";',
                           'log_format example.com "\\"$remote_addr\\""\n    "\\"$msec\\"";')
        self.assertIn('\n    "', ml)
        self.conf.write_text(ml)
        text = self.settle(self.cfg(True))
        # the webspace log is still removed, nothing else is touched
        self.assertNotRegex(text, r"access_log\s+/var/www")
        self.assertEqual(text, ml.replace(
            f"access_log /var/www/{UUID}/logs/webserver.log example.com_persistent;\n", ""))

    def test_every_enhance_log_gets_its_persistent_line(self):
        two = VHOST.replace("include vhost_includes/example.com.conf;\n}\n",
            "include vhost_includes/example.com.conf;\n}\nserver {\nlisten 443;\n"
            f"access_log /var/local/enhance/webserver_logs/{UUID}.log example.com;\n}}\n")
        self.conf.write_text(two)
        text = self.settle(self.cfg(True))
        self.assertEqual(text.count(f"{UUID}/webserver.log example.com_persistent;"), 2)
        self.assertEqual(text.count("log_format example.com_persistent"), 1)

    def test_wrong_destination_is_corrected(self):
        other = "99999999-2222-3333-4444-555555555555"
        self.settle(self.cfg(True))
        self.conf.write_text(self.conf.read_text().replace(f"{UUID}/webserver.log", f"{other}/webserver.log"))
        text = self.settle(self.cfg(True))
        self.assertNotIn(other, text)
        self.assertEqual(text.count(f"{UUID}/webserver.log example.com_persistent;"), 1)

    def test_duplicate_persistent_format_reduced(self):
        text = self.settle(self.cfg(True))
        fmt = [l for l in text.splitlines(keepends=True) if "log_format example.com_persistent" in l][0]
        self.conf.write_text(text.replace(fmt, fmt + fmt))
        text = self.settle(self.cfg(True))
        self.assertEqual(text.count("log_format example.com_persistent"), 1)

    def test_comment_without_semicolon_does_not_eat_directives(self):
        c = VHOST.replace("server {\nlisten 80;",
                          f"# old access_log /var/www/{UUID}/logs/webserver.log\nserver {{\nlisten 80;")
        self.conf.write_text(c)
        for pers in (True, False):
            text = self.settle(self.cfg(pers))
            self.assertIn("server {\nlisten 80;", text)
            self.assertIn(f"# old access_log /var/www/{UUID}/logs/webserver.log\n", text)
            self.assertNotRegex(text, r"(?m)^\s*access_log\s+[\"']?/var/www")

    def test_commented_directives_are_ignored(self):
        c = VHOST.replace("server {\n",
                          "server {\n# log_format old \"$remote_addr\";\n"
                          f"# access_log /var/local/enhance/webserver_logs/99999999-2222-3333-4444-555555555555.log old;\n")
        self.conf.write_text(c)
        text = self.settle(self.cfg(True))
        self.assertIn('# log_format old "$remote_addr";\n', text)
        self.assertEqual(text.count("log_format example.com_persistent"), 1)
        self.assertEqual(text.count(f"{UUID}/webserver.log example.com_persistent;"), 1)
        self.assertNotIn("old_persistent", text)

    def test_multiline_quoted_string_kept(self):
        ml = VHOST.replace("listen 80;", 'listen 80;\nadd_header X-Note "line one;\nline two";')
        self.conf.write_text(ml)
        text = self.settle(self.cfg(True))
        self.assertIn('add_header X-Note "line one;\nline two";', text)
        self.assertEqual(text.count(f"{UUID}/webserver.log example.com_persistent;"), 1)

    def test_unparseable_file_left_untouched(self):
        bad = VHOST.replace("listen 80;", 'listen 80;\nadd_header X-Note "never closed;')
        self.conf.write_text(bad)
        for pers in (True, False):
            self.assertFalse(ngx.apply_logging_features(self.cfg(pers), LOG))
            self.assertEqual(self.conf.read_text(), bad)

    def test_mid_word_quote_is_not_a_string(self):
        c = VHOST.replace("listen 80;", "listen 80;\nrewrite ^/don't-go$ /go permanent;\nlocation /a#b { return 204; }")
        self.conf.write_text(c)
        text = self.settle(self.cfg(True))
        self.assertIn("rewrite ^/don't-go$ /go permanent;", text)
        self.assertIn("location /a#b { return 204; }", text)
        self.assertEqual(text.count(f"{UUID}/webserver.log example.com_persistent;"), 1)

    def test_log_format_with_trailing_comment_supported(self):
        c = VHOST.replace('\\"$msec\\"";', '\\"$msec\\""; # main format')
        self.assertIn("# main format", c)
        self.conf.write_text(c)
        text = self.settle(self.cfg(True))
        self.assertEqual(text.count(f"{UUID}/webserver.log example.com_persistent;"), 1)
        self.assertIn("# main format", text)

    def test_access_log_text_inside_quotes_not_stripped(self):
        q = VHOST.replace("listen 80;", f'listen 80;\nadd_header X-Doc "see access_log /var/www/{UUID}/x.log; docs";')
        self.conf.write_text(q)
        text = self.settle(self.cfg(False))
        self.assertIn(f'add_header X-Doc "see access_log /var/www/{UUID}/x.log; docs";', text)
        self.assertNotRegex(text, r"(?m)^\s*access_log\s+[\"']?/var/www")

    def test_existing_log_file_must_be_regular(self):
        d = ngx.SITE_LOGS_DIR / UUID
        d.mkdir(parents=True)
        (d / "webserver.log").symlink_to(self.tmp / "elsewhere.log")
        text = self.settle(self.cfg(True))
        self.assertNotIn("_persistent", text)
        self.assertFalse((self.tmp / "elsewhere.log").exists())

    def test_format_inserted_only_after_the_real_log_format(self):
        # text "log_format" inside another directive must not be taken for one
        c = 'server {\nlisten 81;\nadd_header X-Note "log_format here";\n}\n' + VHOST.replace(
            '\\"$msec\\"";', '\\"$msec\\""; # main')
        self.conf.write_text(c)
        text = self.settle(self.cfg(True))
        lines = text.splitlines()
        i = next(n for n, l in enumerate(lines) if l.startswith("log_format example.com "))
        self.assertTrue(lines[i + 1].startswith("log_format example.com_persistent "), lines[i:i + 2])
        self.assertEqual(text.count("_persistent '"), 1)
        self.assertIn('add_header X-Note "log_format here";\n}', text)

    def test_quoted_persistent_format_name_replaced_not_duplicated(self):
        text = self.settle(self.cfg(True))
        self.conf.write_text(text.replace("log_format example.com_persistent ",
                                          'log_format "example.com_persistent" '))
        text = self.settle(self.cfg(True))
        self.assertEqual(text.count("example.com_persistent '"), 1)
        self.assertNotIn('"example.com_persistent"', text)

    def test_other_line_breaks_and_escaped_newlines_do_not_shift_lines(self):
        c = ("set $x a\\\nb;\nadd_header X \"form\x0cfeed\x85next\";\n" + VHOST)
        self.conf.write_text(c)
        text = self.settle(self.cfg(True))
        self.assertIn('log_format example.com "', text)
        self.assertEqual(text.count("log_format example.com_persistent '"), 1)
        self.assertEqual(text.count(f"{UUID}/webserver.log example.com_persistent;"), 1)
        self.assertTrue(text.startswith("set $x a\\\nb;\nadd_header X \"form\x0cfeed\x85next\";\n"))

    def test_log_format_on_last_line_without_newline(self):
        c = ("server {\n"
             f"access_log /var/local/enhance/webserver_logs/{UUID}.log example.com;\n"
             '}\nlog_format example.com "$remote_addr";')
        self.conf.write_text(c)
        text = self.settle(self.cfg(True))
        self.assertIn('log_format example.com "$remote_addr";\nlog_format example.com_persistent ', text)
        nc.parse(text)

    def test_variable_access_log_is_kept_not_deleted(self):
        c = VHOST.replace("listen 80;", "listen 80;\naccess_log /var/log/nginx/$host.log example.com;")
        self.conf.write_text(c)
        text = self.settle(self.cfg(False))
        self.assertIn("access_log /var/log/nginx/$host.log example.com;", text)
        # ... and run() refuses to test or reload while it exists
        ngx_conf = self.tmp / "nginx.conf"
        ngx_conf.write_text(f"http {{ include {ngx.SITES_DIR}/*.conf; }}\n")
        self.assertFalse(ngx.log_preflight_ok(LOG, "testing"))

    def test_variable_and_argumentless_logs_under_site_logs_dir_kept(self):
        c = VHOST.replace("listen 80;", f"listen 80;\naccess_log {ngx.SITE_LOGS_DIR}/$host/webserver.log example.com;")
        self.conf.write_text(c)
        text = self.settle(self.cfg(False))
        self.assertIn(f"access_log {ngx.SITE_LOGS_DIR}/$host/webserver.log example.com;", text)
        self.conf.write_text(VHOST.replace("listen 80;", "listen 80;\naccess_log;"))
        ngx.apply_logging_features(self.cfg(True), LOG)       # must not raise

    def test_no_webspace_writes(self):
        # nothing under a fake /var/www may be created by the logging code
        ngx.apply_logging_features(self.cfg(True), LOG)
        self.assertFalse(Path(f"/var/www/{UUID}").exists())


class NginxtuneJsonLoggingTests(unittest.TestCase):
    """json_logging: one JSON object per request, switched in place, never doubled."""

    KEYS = ["time", "msec", "ip", "peer", "cf_ray", "country", "host", "method", "uri",
            "protocol", "status", "bytes_sent", "body_bytes", "request_bytes", "referer",
            "ua", "cache", "request_time", "upstream_time"]

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        ngx_env(self.tmp)
        ngx.SITES_DIR = self.tmp / "sites-enabled"
        ngx.SITES_DIR.mkdir()
        ngx.SITE_LOGS_DIR = self.tmp / "logs"
        self.conf = ngx.SITES_DIR / "example.com.conf"
        self.conf.write_text(VHOST)

    def cfg(self, pers=True, json_on=True, realip=False):
        return {"general": {"persistent_logging": pers},
                "nginx": {"features": {"json_logging": json_on, "real_ip_logging": realip}}}

    def settle(self, cfg):
        ngx.apply_logging_features(cfg, LOG)
        before = self.conf.read_text()
        self.assertFalse(ngx.apply_logging_features(cfg, LOG), "second pass changed the file")
        self.assertEqual(self.conf.read_text(), before)
        return before

    def pers_fmts(self, text):
        return [d for d in nc.parse(text) if d.name == "log_format" and d.args[0].endswith("_persistent")]

    def body(self, d):
        """The format string with every variable replaced, parsed as JSON."""
        import json, re
        self.assertEqual(d.args[1], "escape=json")
        return json.loads(re.sub(r"\$[a-z_0-9]+", "x", d.args[2]))

    def test_enabled_writes_one_json_format_and_log(self):
        text = self.settle(self.cfg())
        fmts = self.pers_fmts(text)
        self.assertEqual(len(fmts), 1)
        self.assertEqual(list(self.body(fmts[0])), self.KEYS)
        self.assertIn('"ip":"$remote_addr"', fmts[0].args[2])
        self.assertEqual(text.count(f"access_log {ngx.SITE_LOGS_DIR}/{UUID}/webserver.log "
                                    "example.com_persistent;"), 1)
        self.assertNotIn("access_log /var/www/", text)
        # the Enhance log and its format are untouched
        self.assertIn(f"access_log /var/local/enhance/webserver_logs/{UUID}.log example.com;", text)
        self.assertIn('log_format example.com "\\"$remote_addr\\" \\"$msec\\"";', text)

    def test_switch_text_json_text_in_place(self):
        text_fmt = self.settle(self.cfg(json_on=False))
        self.assertEqual(len(self.pers_fmts(text_fmt)), 1)
        self.assertNotIn("escape=json", text_fmt)
        as_json = self.settle(self.cfg(json_on=True))
        self.assertEqual(len(self.pers_fmts(as_json)), 1)
        self.assertIn("escape=json", as_json)
        self.assertEqual(as_json.count("_persistent;"), 1)
        back = self.settle(self.cfg(json_on=False))
        self.assertEqual(back, text_fmt)

    def test_real_ip_uses_actual_addr(self):
        text = self.settle(self.cfg(realip=True))
        fmt = self.pers_fmts(text)[0].args[2]
        self.assertIn('"ip":"$actual_addr"', fmt)
        self.assertIn('"peer":"$realip_remote_addr"', fmt)

    def test_disabling_persistent_removes_json_lines(self):
        self.settle(self.cfg())
        text = self.settle(self.cfg(pers=False))
        self.assertEqual(self.pers_fmts(text), [])
        self.assertNotIn("webserver.log", text)

    def test_preflight_accepts_json_vhost(self):
        self.settle(self.cfg())
        (self.tmp / "vhost_includes").mkdir(exist_ok=True)
        (self.tmp / "vhost_includes" / "example.com.conf").write_text("")
        nginx_conf = self.tmp / "nginx.conf"
        nginx_conf.write_text(f"http {{ include {ngx.SITES_DIR}/*; }}\n")
        problems, errors = nc.webspace_log_check(str(nginx_conf), prefix=str(self.tmp))
        self.assertEqual((problems, errors), ([], []))


class NginxtuneRunPreflightTests(unittest.TestCase):
    """run() must not call nginx -t (which opens every log as root) when any
    log destination in the include graph points into a webspace."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.saved = {k: getattr(ngx, k) for k in (
            "NGINX_CONF", "_create_backup", "_restore_backup", "_cleanup_backup",
            "_cleanup_old_backups", "_test_nginx", "_reload_nginx", "apply_nginx_conf",
            "apply_http3_enable", "apply_quic_gso_enable", "_apply_cache_excludes",
            "apply_include_features", "apply_logging_features", "apply_fastcgi_cache_settings",
            "apply_client_max_body_size")}
        self.addCleanup(lambda: [setattr(ngx, k, v) for k, v in self.saved.items()])
        self.calls = []
        ngx.NGINX_CONF = self.tmp / "nginx.conf"
        ngx._create_backup = lambda logger: self.tmp
        ngx._restore_backup = lambda b, logger: self.calls.append("restore") or True
        ngx._cleanup_backup = lambda b, logger: None
        ngx._cleanup_old_backups = lambda days, logger: None
        ngx._test_nginx = lambda: (self.calls.append("test") or (True, ""))
        ngx._reload_nginx = lambda logger: self.calls.append("reload") or True
        for k in ("apply_nginx_conf", "apply_http3_enable", "apply_quic_gso_enable",
                  "_apply_cache_excludes", "apply_include_features", "apply_fastcgi_cache_settings",
                  "apply_client_max_body_size"):
            setattr(ngx, k, lambda config, logger: False)
        ngx.apply_logging_features = lambda config, logger: True

    def test_webspace_log_blocks_nginx_test(self):
        ngx.NGINX_CONF.write_text(f"http {{ access_log /var/www/{UUID}/x.log; }}\n")
        ngx.run({}, LOG)
        self.assertEqual(self.calls, ["restore"])

    def test_restored_config_not_reloaded_when_unsafe(self):
        import logging as _logging
        exits = []
        old_exit, old_shutdown = ngx.os._exit, _logging.shutdown
        ngx.os._exit = lambda code: exits.append(code)
        _logging.shutdown = lambda: None
        self.addCleanup(setattr, ngx.os, "_exit", old_exit)
        self.addCleanup(setattr, _logging, "shutdown", old_shutdown)
        ngx.NGINX_CONF.write_text("http { access_log /var/log/nginx/access.log; }\n")

        def restore(b, logger):
            # the "previous" config that comes back has a webspace log
            ngx.NGINX_CONF.write_text(f"http {{ access_log /var/www/{UUID}/x.log; }}\n")
            self.calls.append("restore")
            return True
        ngx._restore_backup = restore
        ngx._reload_nginx = lambda logger: self.calls.append("reload") or False
        ngx.run({}, LOG)
        self.assertEqual(self.calls, ["test", "reload", "restore"])
        self.assertEqual(exits, [0])

    def test_clean_config_is_tested_and_reloaded(self):
        ngx.NGINX_CONF.write_text("http { access_log /var/log/nginx/access.log; }\n")
        ngx.run({}, LOG)
        self.assertEqual(self.calls, ["test", "reload"])


nrd = load("nginxredirects")


class NginxRedirectsTests(unittest.TestCase):
    """Redirect rules come from the tenant's .htaccess and end up in nginx config
    loaded by root: nothing that could close the location may get through."""

    def item(self, target, pattern=None, code="301", host="^(www.)?example.com$"):
        conds = [{"testString": "%{HTTP_HOST}", "condPattern": host}]
        if pattern is not None:
            conds.append({"testString": "%{REQUEST_URI}", "condPattern": pattern})
        return {"conds": conds, "rule": {"substitution": target, "flags": [f"R={code}"]}}

    def test_plain_rules_translate_as_before(self):
        out = nrd.translate_rules([
            self.item("https://new.example.com%{REQUEST_URI}"),
            self.item("https://new.example.com/b%{REQUEST_URI}", pattern="/old/", code="302"),
        ], LOG)
        self.assertEqual(out["example.com"], [
            "location ~ ^(?!/.well-known)(.*)$ {\n    return 301 https://new.example.com$request_uri;\n}",
            "location ~ ^/old/(.*)$ {\n    return 302 https://new.example.com/b$1;\n}",
        ])
        nc.parse("server {\n" + "\n".join(out["example.com"]) + "\n}\n")

    def test_injection_attempts_are_skipped(self):
        evil_targets = [
            "https://x; } location /l { alias /etc/; } location /y { return 301 y",
            "https://x;fastcgi_pass",
            "https://x}",
            'https://x"',
            "https://x'",
            "#https://x",
            "https://x\nreturn",
            "https://x\\",
        ]
        for t in evil_targets:
            self.assertEqual(nrd.translate_rules([self.item(t)], LOG), {}, t)
        for p in ("/a{2}", "/a b", "/a;", "/a}", "/a#", '/a"'):
            self.assertEqual(nrd.translate_rules([self.item("https://x", pattern=p)], LOG), {}, p)
        for c in ("301;}", "200", "301 x"):
            self.assertEqual(nrd.translate_rules([self.item("https://x", code=c)], LOG), {}, c)
        self.assertEqual(nrd.translate_rules([self.item("https://x", host="^../../etc$")], LOG), {})


class NginxConfTests(unittest.TestCase):
    def names(self, text):
        return [(d.name, d.args) for d in nc.parse(text)]

    def test_tokenizer_like_nginx(self):
        self.assertEqual(self.names('a "b c" \'d\';'), [("a", ["b c", "d"])])
        self.assertEqual(self.names("rewrite ^/don't$ /x; # c ; d;\nlocation /a#b { e f; }"),
                         [("rewrite", ["^/don't$", "/x"]), ("location", ["/a#b"]), ("e", ["f"])])
        self.assertEqual(self.names('set $x "${host}a"; return 200 ${y}z;'),
                         [("set", ["$x", "${host}a"]), ("return", ["200", "${y}z"])])
        self.assertEqual(self.names('if ($a != "") { b; }'), [("if", ["($a", "!=", "", ")"]), ("b", [])])
        self.assertEqual(self.names('a "q\\"uote";'), [("a", ['q"uote'])])
        self.assertEqual(self.names('add_header X "multi\nline";'), [("add_header", ["X", "multi\nline"])])
        # '}' inside a token is literal; only at token start does it close a block
        self.assertEqual(self.names("location ~ ^/docs/[}]$ { return 204; }"),
                         [("location", ["~", "^/docs/[}]$"]), ("return", ["204"])])
        # after "${" nginx tokenizes normally again
        self.assertEqual(self.names("set $x ${a}b;"), [("set", ["$x", "${a}b"])])
        # an escaped newline inside a token still counts as a line
        self.assertEqual([d.line_start for d in nc.parse("a b\\\nc;\nd;")], [0, 2])
        # block context
        ctx = {d.name: d.ctx for d in nc.parse("http { server { location / { x; } } map $a $b { y z; } }")}
        self.assertEqual(ctx["x"], ("http", "server", "location"))
        self.assertEqual(ctx["y"], ("http", "map"))
        for bad in ('a "open;', "a {", "}", "a; }", ";", 'a "x"y;', "a"):
            with self.assertRaises(nc.ConfError, msg=bad):
                nc.parse(bad)

    def test_sole_on_line_and_remove(self):
        t = "a 1;\n  b 2; # note\nc 3; d 4;\ne {\nf 5; }\ng\n  6;\n"
        ds = nc.parse(t)
        sole = nc.sole_on_line(t, ds)
        self.assertEqual(sorted((ln, d.name) for ln, d in sole.items()), [(0, "a"), (1, "b")])
        out = nc.remove_directives(t, [d for d in ds if d.name in ("a", "c", "f", "g")])
        self.assertEqual(out, "  b 2; # note\n d 4;\ne {\n }\n")

    def _tree(self):
        root = Path(tempfile.mkdtemp())
        (root / "conf.d").mkdir()
        return root

    def test_include_graph_and_webspace_logs(self):
        root = self._tree()
        (root / "nginx.conf").write_text("http { include conf.d/*.conf; include extra.conf; }\n")
        (root / "extra.conf").write_text("access_log /var/log/nginx/a.log;\n")
        (root / "conf.d" / "a.conf").write_text(
            "server { location /a#b { access_log /var/www/x/y.log; } }\n")
        problems, errors = nc.webspace_log_check(str(root / "nginx.conf"), prefix=str(root))
        self.assertEqual(errors, [])
        self.assertEqual(len(problems), 1)
        self.assertIn("/var/www/x/y.log", problems[0])

    def test_include_patterns_and_occurrences(self):
        root = self._tree()
        (root / "conf.d" / "[legacy]-a.conf").write_text("x;\n")
        locked = root / "locked"
        locked.mkdir()
        (root / "inc.conf").write_text("y;\n")
        (root / "loop.conf").write_text(f"include {root}/loop.conf;\n")
        (root / "nginx.conf").write_text(
            f"include conf.d/\\[legacy\\]-*.conf;\n"          # libc-only escaping: refused
            "http { include inc.conf; server { include inc.conf; } }\n"
            "map $a $b { include missing-map.conf; }\n"
            "include loop.conf;\n"
            "include no-such-dir/*.conf;\n")                  # nothing to load, like nginx
        files, errors = nc.include_graph(str(root / "nginx.conf"))
        self.assertTrue(any("unsupported include pattern" in e for e in errors), errors)
        self.assertTrue(any("missing-map.conf" in e for e in errors), errors)
        self.assertTrue(any("include cycle" in e for e in errors), errors)
        self.assertFalse(any("no-such-dir" in e for e in errors), errors)
        # the same file loaded in two places appears twice, with each context
        self.assertEqual(sorted(g.base for g in files if g.file.endswith("inc.conf")),
                         [("http",), ("http", "server")])
        if not AS_ROOT:
            os.chmod(locked, 0o000)
            self.addCleanup(os.chmod, locked, 0o700)
            (root / "nginx.conf").write_text(f"include {locked}/*.conf;\n")
            _, errors = nc.include_graph(str(root / "nginx.conf"))
            self.assertEqual(len(errors), 1, errors)

    def test_include_question_mark_and_dotfiles(self):
        root = self._tree()
        (root / "conf.d" / "a.conf").write_text("x;\n")
        (root / "conf.d" / ".hidden.conf").write_text("y;\n")
        (root / "nginx.conf").write_text("include conf.d/*.conf;\n")
        files, errors = nc.include_graph(str(root / "nginx.conf"))
        self.assertEqual(errors, [])
        self.assertEqual(sorted(os.path.basename(g.file) for g in files), ["a.conf", "nginx.conf"])
        for pat in ("conf.d/?.conf", "conf.d/\u00e9*.conf"):
            (root / "nginx.conf").write_text(f"include {pat};\n")
            _, errors = nc.include_graph(str(root / "nginx.conf"))
            self.assertTrue(any("unsupported include pattern" in e for e in errors), (pat, errors))

    def test_missing_literal_include_is_an_error(self):
        root = self._tree()
        (root / "nginx.conf").write_text("include missing.conf; include conf.d/none-*.conf;\n")
        problems, errors = nc.webspace_log_check(str(root / "nginx.conf"), prefix=str(root))
        self.assertEqual(len(errors), 1)
        self.assertIn("missing.conf", errors[0])

    def test_variable_prefix_through_symlinks_and_double_slash(self):
        root = self._tree()
        www = Path(tempfile.mkdtemp())
        old = nc.WWW_DIR
        nc.WWW_DIR = str(www)
        self.addCleanup(setattr, nc, "WWW_DIR", old)
        (root / "v").symlink_to(www.parent)          # a link to an ancestor of the webspace root
        (root / "nginx.conf").write_text(
            "access_log //$x;\n"
            f"access_log {root}/v/{www.name[:4]}$x;\n"   # resolves to a prefix of the webspace
            f"access_log {root}/v/$x;\n"                # a directory above it
            f"access_log {root}/v/{www.name}x/$x;\n")   # a value with '../' could still escape
        problems, errors = nc.webspace_log_check(str(root / "nginx.conf"), prefix=str(root))
        self.assertEqual(errors, [])
        self.assertEqual(len(problems), 4, problems)

    def test_special_destinations_per_directive(self):
        root = self._tree()
        www = Path(tempfile.mkdtemp())
        old = nc.WWW_DIR
        nc.WWW_DIR = str(www)
        self.addCleanup(setattr, nc, "WWW_DIR", old)
        (www / "site").mkdir()
        for name in ("off", "stderr", "memory:x"):
            (root / name).symlink_to(www / "site" / name)
        (root / "nginx.conf").write_text(
            "access_log off; error_log stderr; error_log memory:1m; access_log syslog:server=x;\n"
            "error_log off; access_log stderr; access_log memory:x;\n")   # literal files here
        problems, errors = nc.webspace_log_check(str(root / "nginx.conf"), prefix=str(root))
        self.assertEqual(errors, [])
        self.assertEqual(len(problems), 3, problems)

    def test_symlink_chain_and_relative_includes(self):
        root = self._tree()
        www = Path(tempfile.mkdtemp())
        old = nc.WWW_DIR
        nc.WWW_DIR = str(www)
        self.addCleanup(setattr, nc, "WWW_DIR", old)
        (www / "site").mkdir()
        outside = Path(tempfile.mkdtemp())
        # a directory link into the webspace, whose file links back out again
        (root / "site-logs").symlink_to(www / "site")
        (www / "site" / "a.log").symlink_to(outside / "a.log")
        # '..' after a symlink means what the kernel makes of it
        (root / "deep").symlink_to(www / "site")
        (root / "conf.d" / "x.conf").write_text("access_log site-logs/a.log; error_log deep/../b.log;\n"
                                                 f"map $a $b {{ access_log {www}/site/not-a-directive; }}\n")
        # includes resolve against the main config's directory, not the prefix
        (root / "nginx.conf").write_text("include conf.d/*.conf;\n")
        problems, errors = nc.webspace_log_check(str(root / "nginx.conf"), prefix=str(root))
        self.assertEqual(errors, [])
        self.assertEqual(len(problems), 2, problems)
        other_prefix = Path(tempfile.mkdtemp())
        files, errors = nc.include_graph(str(root / "nginx.conf"), prefix=str(other_prefix))
        self.assertEqual((len(files), errors), (2, []))

    def test_symlink_hop_through_webspace_detected(self):
        root = self._tree()
        www = Path(tempfile.mkdtemp())
        old = nc.WWW_DIR
        nc.WWW_DIR = str(www)
        self.addCleanup(setattr, nc, "WWW_DIR", old)
        (www / "site").mkdir()
        outside = Path(tempfile.mkdtemp())
        # trusted link -> link inside the webspace (tenant controlled) -> back outside
        (www / "site" / "hop").symlink_to(outside / "target.log")
        (root / "x.log").symlink_to(www / "site" / "hop")
        (root / "nginx.conf").write_text(f"access_log {root}/x.log; access_log {outside}/ok.log;\n")
        problems, errors = nc.webspace_log_check(str(root / "nginx.conf"), prefix=str(root))
        self.assertEqual(errors, [])
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("x.log", problems[0])
        # a symlink loop cannot be judged: refused
        (root / "loop1").symlink_to(root / "loop2")
        (root / "loop2").symlink_to(root / "loop1")
        (root / "nginx.conf").write_text(f"access_log {root}/loop1/a.log;\n")
        problems, _ = nc.webspace_log_check(str(root / "nginx.conf"), prefix=str(root))
        self.assertEqual(len(problems), 1)

    def test_uninspectable_path_component_refused(self):
        if AS_ROOT:
            self.skipTest("root can inspect any directory")
        root = self._tree()
        locked = root / "locked"
        (locked / "sub").mkdir(parents=True)
        os.chmod(locked, 0o000)
        self.addCleanup(os.chmod, locked, 0o700)
        (root / "nginx.conf").write_text(f"access_log {locked}/sub/a.log;\n")
        problems, errors = nc.webspace_log_check(str(root / "nginx.conf"), prefix=str(root))
        self.assertEqual(len(problems), 1, problems)

    def test_symlink_into_webspace_and_variables_detected(self):
        root = self._tree()
        www = Path(tempfile.mkdtemp())
        old = nc.WWW_DIR
        nc.WWW_DIR = str(www)
        self.addCleanup(setattr, nc, "WWW_DIR", old)
        (www / "site").mkdir()
        (root / "logs").symlink_to(www / "site")
        (root / "nginx.conf").write_text(
            "access_log logs/a.log;\n"                     # relative, through a symlink
            "access_log $var/b.log;\n"                     # cannot be judged
            f"access_log {www}/site/$host.log;\n"          # variable inside the webspace
            f"access_log {www}$x;\n"                       # the variable may start with '/'
            f"error_log {www}/site/$x.log;\n"              # error_log: literal path, inside
            "error_log $var/c.log;\n"                      # literal path below the prefix: fine
            f"access_log {str(www)[:-2]}$x;\n"             # the variable can complete the webspace path
            "access_log /$x;\n"
            f"access_log {str(www)[:-2]}/$host.log;\n"     # any variable: refused
            "access_log off; error_log stderr; access_log syslog:server=x;\n"
            f"access_log {root}/fine.log;\n")
        problems, errors = nc.webspace_log_check(str(root / "nginx.conf"), prefix=str(root))
        self.assertEqual(errors, [])
        # every access_log with a variable is refused; error_log is literal
        self.assertEqual(len(problems), 8, problems)
        self.assertFalse(any("c.log" in p for p in problems))


if __name__ == "__main__":
    unittest.main(verbosity=2)
