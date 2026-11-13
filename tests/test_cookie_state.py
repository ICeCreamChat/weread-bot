import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
from cryptography.fernet import Fernet

from tests.helpers import FakeHttpClient, load_weread_bot


def sample_curl(seed="initial-session-key"):
    """只包含虚构认证数据，不会向微信读书发起请求。"""
    payload = {
        "appId": "test-app", "ps": "test-ps", "pc": "test-pc",
        "b": "sample-book-id", "c": "sample-chapter-id", "ci": 0,
    }
    return (
        "curl 'https://weread.qq.com/web/book/read' "
        "-H 'User-Agent: Mozilla/5.0' "
        f"-b 'wr_skey={seed}; wr_rt=initial-refresh-token' "
        f"--data-raw '{json.dumps(payload)}'"
    )


class CookieStateTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.bot = load_weread_bot()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.state_path = Path(self.temp_dir.name) / "session.enc"
        self.key = Fernet.generate_key().decode("ascii")
        self.env = patch.dict(os.environ, {
            "WEREAD_SESSION_STATE_FILE": str(self.state_path),
            "WEREAD_SESSION_STATE_KEY": self.key,
        })
        self.env.start()
        self.addCleanup(self.env.stop)

    async def session(self, seed="initial-session-key"):
        config = self.bot.WeReadConfig(
            curl_content=sample_curl(seed),
            reading=self.bot.ReadingConfig(
                books=[self.bot.BookInfo(
                    name="Sample", book_id="sample-book-id",
                    chapters=["sample-chapter-id"],
                )],
            ),
            human_simulation=self.bot.HumanSimulationConfig(enabled=False),
        )
        with patch.object(self.bot, "HttpClient", return_value=FakeHttpClient()):
            session = self.bot.WeReadSessionManager(config)
        return session

    async def refresh(self, session, skey="renewed-session-key"):
        response = httpx.Response(200, request=httpx.Request(
            "POST", "https://weread.qq.com/web/login/renewal"
        ), headers=[
            ("set-cookie", f"wr_skey={skey}; Path=/; Secure; HttpOnly"),
            ("set-cookie", "wr_rt=renewed-refresh-token; Path=/; Secure"),
        ])
        session.http_client = FakeHttpClient(raw_responses=[(response, 0.01)])
        return await session._refresh_cookie()

    async def test_new_session_uses_previous_refresh_without_plaintext_file(self):
        first = await self.session()
        self.assertTrue(await self.refresh(first))

        second = await self.session()

        self.assertEqual(second.cookies["wr_skey"], "renewed-session-key")
        self.assertEqual(second.cookies["wr_rt"], "renewed-refresh-token")
        ciphertext = self.state_path.read_bytes()
        self.assertNotIn(b"renewed-session-key", ciphertext)
        self.assertNotIn(b"renewed-refresh-token", ciphertext)
        Fernet(self.key.encode()).decrypt(ciphertext)

    async def test_tampered_state_stops_before_authenticating(self):
        self.state_path.write_bytes(b"invalid-encrypted-state")

        with self.assertLogs(level="ERROR"):
            with self.assertRaisesRegex(ValueError, "加密登录状态"):
                await self.session()

    async def test_manually_updated_curl_takes_precedence_over_saved_state(self):
        first = await self.session()
        self.assertTrue(await self.refresh(first))

        replacement = await self.session("manually-replaced-session")

        self.assertEqual(replacement.cookies["wr_skey"], "manually-replaced-session")
        self.assertEqual(replacement.cookies["wr_rt"], "initial-refresh-token")

    async def test_wrong_key_cannot_silently_replace_existing_state(self):
        first = await self.session()
        self.assertTrue(await self.refresh(first))
        previous_state = self.state_path.read_bytes()

        with patch.dict(os.environ, {
            "WEREAD_SESSION_STATE_KEY": Fernet.generate_key().decode("ascii")
        }), self.assertLogs(level="ERROR"):
            with self.assertRaisesRegex(ValueError, "加密登录状态"):
                await self.session()

        self.assertEqual(self.state_path.read_bytes(), previous_state)

    async def test_both_settings_are_required_to_enable_persistence(self):
        with patch.dict(os.environ, {"WEREAD_SESSION_STATE_KEY": ""}):
            with self.assertRaisesRegex(ValueError, "必须同时设置"):
                await self.session()

    async def test_unconfigured_sessions_keep_existing_in_memory_behavior(self):
        with patch.dict(os.environ, {
            "WEREAD_SESSION_STATE_KEY": "", "WEREAD_SESSION_STATE_FILE": "",
        }):
            first = await self.session()
            self.assertTrue(await self.refresh(first))
            second = await self.session()

        self.assertEqual(first.cookies["wr_skey"], "renewed-session-key")
        self.assertEqual(second.cookies["wr_skey"], "initial-session-key")
        self.assertFalse(self.state_path.exists())

    async def test_separate_users_keep_their_own_updated_cookies(self):
        first = await self.session("first-seed-session")
        second = await self.session("second-seed-session")
        self.assertTrue(await self.refresh(first, "first-renewed-session"))
        self.assertTrue(await self.refresh(second, "second-renewed-session"))

        first_restored = await self.session("first-seed-session")
        second_restored = await self.session("second-seed-session")

        self.assertEqual(first_restored.cookies["wr_skey"], "first-renewed-session")
        self.assertEqual(second_restored.cookies["wr_skey"], "second-renewed-session")

    async def test_failed_refresh_preserves_last_saved_credentials(self):
        first = await self.session()
        self.assertTrue(await self.refresh(first))
        second = await self.session()
        second.http_client = FakeHttpClient(raw_responses=[
            (httpx.Response(200, request=httpx.Request(
                "POST", "https://weread.qq.com/web/login/renewal"
            )), 0.01) for _ in range(3)
        ])
        with self.assertLogs(level="ERROR"):
            self.assertFalse(await second._refresh_cookie())

        restored = await self.session()
        self.assertEqual(restored.cookies["wr_skey"], "renewed-session-key")

    async def test_failed_write_is_reported_without_overwriting_previous_state(self):
        first = await self.session()
        self.assertTrue(await self.refresh(first))
        self.assertTrue(self.state_path.exists())
        previous_state = self.state_path.read_bytes()

        with patch.object(self.bot.os, "replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                await self.refresh(first, "another-renewed-session")

        self.assertEqual(self.state_path.read_bytes(), previous_state)


if __name__ == "__main__":
    unittest.main()
