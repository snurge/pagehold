import unittest

import app


class BrowserRenderingTests(unittest.TestCase):
    def test_does_not_render_normal_html(self):
        body = b"<html><body><h1>Archived page</h1><p>Useful static content.</p></body></html>"
        self.assertFalse(app.needs_browser_render(body))


class LocalAccessTests(unittest.TestCase):
    def setUp(self):
        self.owner = {"id": "usr_owner", "role": "user"}
        self.other = {"id": "usr_other", "role": "user"}
        self.public = {
            "id": "site_public",
            "owner_id": self.owner["id"],
            "visibility": "public",
        }
        self.private = {**self.public, "id": "site_private", "visibility": "private"}

    def test_public_archives_are_visible_and_private_archives_are_not(self):
        self.assertTrue(app.can_view_site(None, self.public))
        self.assertFalse(app.can_view_site(None, self.private))
        self.assertTrue(app.can_view_site(self.owner, self.private))
        self.assertFalse(app.can_view_site(self.other, self.private))

    def test_only_the_local_owner_can_manage_archives(self):
        self.assertTrue(app.can_manage_site(self.owner, self.public))
        self.assertFalse(app.can_manage_site(self.other, self.public))
        self.assertFalse(app.can_manage_site(None, self.public))


if __name__ == "__main__":
    unittest.main()
