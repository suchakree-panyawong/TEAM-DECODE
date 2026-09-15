import importlib
import unittest
import base64
import json
import subprocess
import sys
from pathlib import Path

from core.engine import auto_decode
from core.registry import get_all_decoders
import decoders
from decoders.ciphers import decode_morse, decode_bacon
from decoders import base_decoders


class RegressionTests(unittest.TestCase):
    ROOT = Path(__file__).resolve().parent.parent

    def test_base64url_preserves_urlsafe_chars(self) -> None:
        original = "\x03\xe0"
        payload = "A-A="
        self.assertIn("-", payload)
        self.assertEqual(base_decoders.decode_base64url(payload), original)

    def test_base64_and_base16_still_decode_with_noise_separators(self) -> None:
        self.assertEqual(base_decoders.decode_base64("SGV sbG8g V29 ybGQ="), "Hello World")
        self.assertEqual(base_decoders.decode_base16("48 65 6c 6c 6f 20 57 6f 72 6c 64"), "Hello World")

    def test_decoder_registry_stays_stable_after_reload(self) -> None:
        before = len(get_all_decoders())
        importlib.reload(base_decoders)
        after = len(get_all_decoders())
        self.assertEqual(before, after)

    def test_morse_decoder_is_registered_and_decodes(self) -> None:
        self.assertTrue(any(d['name'] == 'morse' for d in get_all_decoders()))
        text = decode_morse('- . .- -- .. ... .-. .. -.-. .... -- .- -. .- -. -.. .... .- .--. .--. -.-- -- .- -. - .... . -- --- ... - / .. -. - .... . .-- --- .-. .-.. -..')
        self.assertEqual(text, 'TEAMISRICHMANANDHAPPYMANTHEMOST INTHEWORLD')

    def test_bacon_decoder_handles_short_standard_payloads(self) -> None:
        self.assertEqual(decode_bacon('AAAAA AAAAB'), 'AB')

    def test_auto_decode_prefers_the_direct_morse_chain(self) -> None:
        import base64
        payload = base64.b64encode(b'- . ... -').decode()
        candidates = auto_decode(payload, max_depth=4, beam_size=50)
        self.assertTrue(candidates)
        self.assertEqual(candidates[0].text, 'TEST')

    def test_auto_decode_prefers_reverse_plaintext(self) -> None:
        payload = 'dleihS remmacS rebyC'
        candidates = auto_decode(payload, max_depth=4, beam_size=50)
        self.assertTrue(candidates)
        self.assertEqual(candidates[0].text, 'Cyber Scammer Shield')

    def test_auto_decode_prefers_plaintext_like_output_over_gibberish(self) -> None:
        payload = '010000010100001001000011'
        candidates = auto_decode(payload, max_depth=4, beam_size=50)
        self.assertTrue(candidates)
        self.assertEqual(candidates[0].text, 'ABC')

    def test_cli_supports_stdin_scheme_filter_and_confidence(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(self.ROOT / 'TEAM-DECODE.py'), '--stdin', '--json', '--scheme', 'base64'],
            input='SGVsbG8=', text=True, capture_output=True, cwd=self.ROOT, check=True,
        )
        result = json.loads(proc.stdout)
        self.assertEqual(result['winner']['text'], 'Hello')
        self.assertEqual(result['winner']['confidence'], 'high')


if __name__ == "__main__":
    unittest.main()
