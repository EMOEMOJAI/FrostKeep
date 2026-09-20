import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('check_docs', Path(__file__).resolve().parents[1] / 'scripts/check-docs.py')
docs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(docs)


class DocumentationTests(unittest.TestCase):
    def fixture(self, text, guide='# Recovery\n'):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / 'RELEASE_FILES').write_text('README.md\nguide.md\nllms.txt\nicon.png\n')
        (root / 'README.md').write_text(text)
        (root / 'guide.md').write_text(guide)
        (root / 'llms.txt').write_text('')
        (root / 'icon.png').write_bytes(b'fixture')
        return root

    def test_valid_anchors_images_and_fenced_examples(self):
        root = self.fixture('[Restore](guide.md#recovery-1)\n<img src="icon.png">\n'
                            '```sh\n[example](absent.md)\n```\n', '# Recovery\n# Recovery\n')
        self.assertEqual(docs.check(root), (2, []))

    def test_broken_heading_and_image_fail(self):
        root = self.fixture('[Restore](guide.md#removed)\n![art](missing.png)\n')
        self.assertEqual(len(docs.check(root)[1]), 2)

    def test_llms_github_links_resolve_locally_without_network(self):
        root = self.fixture('')
        (root / 'llms.txt').write_text(f'[Guide]({docs.REPOSITORY}/blob/main/deleted.md)')
        self.assertEqual(len(docs.check(root)[1]), 1)

    def test_nonpublic_and_parent_targets_fail(self):
        root = self.fixture('[private](notes.md)\n[outside](../secret.md)\n')
        (root / 'notes.md').write_text('Not allowlisted')
        self.assertEqual(len(docs.check(root)[1]), 2)

    def test_external_links_are_not_fetched(self):
        root = self.fixture('[External](https://example.invalid/unreachable)\n[ref]: guide.md#recovery\n')
        self.assertEqual(docs.check(root), (1, []))
