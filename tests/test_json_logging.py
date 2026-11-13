import io
import json
import logging
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from tests.helpers import load_weread_bot


class JsonLoggingTests(unittest.TestCase):
    def test_json_formatter_escapes_arbitrary_message(self):
        bot = load_weread_bot()
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.addFilter(bot.LogContextFilter())
        handler.setFormatter(bot.JsonLogFormatter())
        logger = logging.getLogger(f"json-test-{id(self)}")
        logger.handlers = [handler]
        logger.propagate = False
        logger.setLevel(logging.INFO)

        logger.info('引号 " 反斜线 \\ 和换行\n下一行')

        payload = json.loads(stream.getvalue())
        self.assertEqual(payload["user"], "system")
        self.assertEqual(payload["session_id"], "-")
        self.assertIn("下一行", payload["message"])

    def test_setup_logging_uses_json_formatter_for_every_line(self):
        bot = load_weread_bot()
        root_logger = logging.getLogger()
        with tempfile.TemporaryDirectory() as temp_dir, \
                patch.object(root_logger, "handlers", []), \
                patch.object(root_logger, "level", root_logger.level):
            log_path = Path(temp_dir) / "test.log"
            bot.setup_logging(
                bot.LoggingConfig(
                    level="INFO",
                    format="json",
                    file=str(log_path),
                    console=False,
                )
            )
            try:
                logging.info('中文 "quoted"\nline')
                for handler in root_logger.handlers:
                    handler.flush()
                lines = log_path.read_text(encoding="utf-8").splitlines()
            finally:
                for handler in root_logger.handlers[:]:
                    root_logger.removeHandler(handler)
                    handler.close()

        self.assertEqual(len(lines), 1)
        payload = json.loads(lines[0])
        self.assertEqual(payload["user"], "system")
        self.assertEqual(payload["session_id"], "-")


if __name__ == "__main__":
    unittest.main()
