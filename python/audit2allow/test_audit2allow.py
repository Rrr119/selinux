import unittest
import os
import os.path
import sys
from tempfile import mkdtemp
from subprocess import Popen, PIPE


class Audit2allowTests(unittest.TestCase):

    def assertDenied(self, err):
        self.assertTrue('Permission denied' in err,
                        '"Permission denied" not found in %r' % err)

    def assertNotFound(self, err):
        self.assertTrue('not found' in err,
                        '"not found" not found in %r' % err)

    def assertFailure(self, status):
        self.assertTrue(status != 0,
                        '"Succeeded when it should have failed')

    def assertSuccess(self, cmd, status, err):
        self.assertTrue(status == 0,
                        '"%s should have succeeded for this test %r' % (cmd, err))

    def test_sepolgen_ifgen(self):
        "Verify sepolgen-ifgen works"
        temp_directory = mkdtemp(suffix='audit2allow_test')
        output_file = os.path.join(temp_directory, 'interface_info')
        p = Popen([
            sys.executable, './sepolgen-ifgen', '-p', 'test_dummy_policy', '-o', output_file,
            '--attr-helper', './sepolgen-ifgen-attr-helper'
            ], stdout=PIPE)
        out, err = p.communicate()
        if err:
            print(out, err)
        self.assertSuccess("sepolgen-ifgen", p.returncode, err)
        os.unlink(output_file)
        os.rmdir(temp_directory)

    def test_audit2allow(self):
        "Verify audit2allow works"
        p = Popen([sys.executable, './audit2allow', '-p', 'test_dummy_policy', '-i', 'test.log'], stdout=PIPE)
        out, err = p.communicate()
        if err:
            print(out, err)
        self.assertSuccess("audit2allow", p.returncode, err)
        self.assertNotIn(b"AVC denials grouped by process and path", out)

    def test_audit2why(self):
        "Verify audit2why works"
        p = Popen([sys.executable, './audit2why', '-p', 'test_dummy_policy', '-i', 'test.log'], stdout=PIPE)
        out, err = p.communicate()
        if err:
            print(out, err)
        self.assertSuccess("audit2why", p.returncode, err)

    def test_xperms(self):
        "Verify that xperms generation works"
        p = Popen([sys.executable, './audit2allow', '-x', '-p', 'test_dummy_policy', '-i', 'test.log'], stdout=PIPE)
        out, err = p.communicate()
        if err:
            print(out, err)
        self.assertTrue(b"allowxperm" in out)
        self.assertSuccess("xperms", p.returncode, err)

    def test_aggregate_denial_by_process_and_path(self):
        "Verify denials are grouped by process and path with minimal rules"
        p = Popen([
            sys.executable, './audit2allow', '-p', 'test_dummy_policy',
            '-i', 'test_denial.log', '--aggregate'
            ], stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        if err:
            print(out, err)
        self.assertSuccess("aggregate", p.returncode, err)

        self.assertIn(b"process: /usr/sbin/httpd (httpd)", out)
        self.assertIn(b"path: /etc/myapp/app.conf", out)
        self.assertIn(b"path: /var/www/html/index.html", out)
        self.assertIn(b"denied: open read", out)
        self.assertIn(b"count: 2", out)
        self.assertIn(
            b"suggestion: allow httpd_t usr_t:file { open read };", out)
        self.assertIn(b"allow httpd_t usr_t:file { open read };", out)
        self.assertIn(
            b"allow httpd_t var_t:file execute_no_trans;", out)


if __name__ == "__main__":
    unittest.main()
