import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import radar


class ReceiptTests(unittest.TestCase):
    def test_candidate_keeps_initial_price(self):
        now = 1_800_000_000_000
        mint, pair = "A" * 32, "B" * 32
        row = {"chainId":"solana", "baseToken":{"address":mint,"name":"Token","symbol":"TOK"},
               "pairAddress":pair, "pairCreatedAt":now-3_600_000, "priceUsd":"0.0125",
               "liquidity":{"usd":50000}, "volume":{"h1":80000,"m5":12000},
               "txns":{"h1":{"buys":100,"sells":50}}, "priceChange":{"h1":20,"m5":4}}
        candidate = radar.qualify("solana", row, {mint}, now)
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.price_usd, 0.0125)

    def test_24h_receipt_tracks_and_publishes_once(self):
        sent_at = (datetime.now(timezone.utc)-timedelta(hours=25)).isoformat()
        history = {"solana:"+"A"*32:{"status":"sent","sent_at":sent_at,"chain":"solana",
                   "mint":"A"*32,"pair":"B"*32,"symbol":"TOK","score":81,
                   "initial_price":1.0,"tracking":{}}}
        with patch.object(radar,"current_market",return_value={"price":1.25,"liquidity":50000}), \
             patch.object(radar,"save_history") as saved, patch.object(radar,"send",return_value=99) as sent:
            failures=radar.update_receipts(history,"token","@channel","channel","refs/heads/main")
        self.assertEqual(failures,0)
        entry=history["solana:"+"A"*32]
        self.assertEqual(entry["tracking"]["24h"]["change_pct"],25.0)
        self.assertEqual(entry["receipt_message_id"],99)
        self.assertEqual(sent.call_count,1)
        self.assertGreaterEqual(saved.call_count,2)


if __name__ == "__main__":
    unittest.main()
