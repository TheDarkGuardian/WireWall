"""Offline tests only: importing these helpers never creates a socket."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import sys
from unittest import mock

sys.dont_write_bytecode = True

SOURCE = Path(__file__).resolve().parents[1] / "linux" / "bench_traffic.py"
SPEC = importlib.util.spec_from_file_location("wirewall_benchmark", SOURCE)
BENCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCH)


class ValidationTests(unittest.TestCase):
    def test_bounds_and_finite_values(self):
        BENCH.validate_rates(30, 5000, 45000)
        BENCH.validate_rates(0.1, 1, 0)
        for duration, legitimate, background in ((0, 1, 0), (30.1, 1, 0), (float("nan"), 1, 0),
                                                (float("inf"), 1, 0), (1, 0, 0), (1, 5001, 0),
                                                (1, 1, -1), (1, 1, 50000)):
            with self.subTest(duration=duration, legitimate=legitimate, background=background):
                with self.assertRaises(ValueError):
                    BENCH.validate_rates(duration, legitimate, background)

    def test_target_is_literal_and_fixed(self):
        self.assertEqual(BENCH.validate_target("10.203.0.2"), "10.203.0.2")
        for target in ("example.com", "127.0.0.1", "10.203.0.3", "203.0.113.10", "::1"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                BENCH.validate_target(target)

    def test_bad_arguments_fail_before_any_socket_creation(self):
        with mock.patch.object(BENCH.socket, "socket", side_effect=AssertionError("network used")):
            with self.assertRaises(ValueError):
                BENCH.run_client(1, 100, 100, "203.0.113.10")
            with self.assertRaises(ValueError):
                BENCH.run_client(31, 100, 100, "10.203.0.2")

    def test_traffic_requires_all_isolation_conditions(self):
        with mock.patch.object(BENCH.platform, "system", return_value="Windows"):
            with self.assertRaises(RuntimeError):
                BENCH.require_isolated_namespace()
        with mock.patch.object(BENCH.platform, "system", return_value="Linux"), \
             mock.patch.dict(BENCH.os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError):
                BENCH.require_isolated_namespace()
        with mock.patch.object(BENCH.platform, "system", return_value="Linux"), \
             mock.patch.dict(BENCH.os.environ, {"WIREWALL_ALLOW_NETNS_BENCHMARK":"1"}, clear=True), \
             mock.patch.object(BENCH.os, "geteuid", create=True, return_value=0), \
             mock.patch.object(BENCH.os, "readlink", return_value="net:[1]"):
            with self.assertRaises(RuntimeError):
                BENCH.require_isolated_namespace()


class StatisticsTests(unittest.TestCase):
    def test_pacing_never_sends_before_due_and_caps_catchup(self):
        self.assertEqual(BENCH.due_packets(0.9999,1.0,500),0)
        self.assertEqual(BENCH.due_packets(1.0,1.0,500),1)
        self.assertEqual(BENCH.due_packets(2.0,1.0,500),64)

    def test_nearest_rank_and_missing_observations(self):
        self.assertIsNone(BENCH.percentile([], 0.95))
        self.assertEqual(BENCH.percentile([10, 1, 3, 2], 0.5), 2)
        self.assertEqual(BENCH.percentile(list(range(1, 101)), 0.95), 95)
        self.assertEqual(BENCH.percentile([4], 0.95), 4)
        for values, fraction in (([1], 0), ([float("nan")], 0.95), ([-1], 0.95)):
            with self.assertRaises(ValueError):
                BENCH.percentile(values, fraction)

    def test_process_cpu_does_not_misparse_spaces_in_comm(self):
        fields = ["S"] + ["0"] * 10 + ["123", "45"] + ["0"] * 10
        got = BENCH.parse_proc_cpu("42 (echo ) process) " + " ".join(fields), 100)
        self.assertEqual(got, {"userSeconds":1.23, "systemSeconds":0.45})
        with self.assertRaises(ValueError):
            BENCH.parse_proc_cpu("broken", 100)

    def test_host_cpu_is_separately_scoped_and_does_not_double_count_guest(self):
        before=BENCH.parse_host_cpu("cpu 10 0 10 100 5 0 1 2 50 0\n",100)
        after=BENCH.parse_host_cpu("cpu 20 0 20 110 5 0 3 3 90 0\n",100)
        delta=BENCH.host_cpu_delta(before,after)
        self.assertEqual(delta["softirqSeconds"],0.02)
        self.assertEqual(delta["stealSeconds"],0.01)
        self.assertAlmostEqual(delta["busyPercent"],23*100/33)
        self.assertIn("shared",before["scope"])
        with self.assertRaises(ValueError):BENCH.host_cpu_delta(after,before)

    def test_summary_retains_real_counts_missing_rtt_and_repetitions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, ratio, latency in ((1, 0.9, 4.0), (2, 1.0, None)):
                run = root / f"run-{index:03}-nft-{index}"
                run.mkdir()
                BENCH.write_json(run/"run.json", {"mode":"nft", "repetition":index})
                BENCH.write_json(run/"client.json", {
                    "streams":{"legitimate":{"offeredPPS":98.0,"successRatio":ratio},
                               "background":{"offeredPPS":900.0,"successRatio":0.0}},
                    "legitimateRTT":{"p95Milliseconds":latency},
                    "clientProcessCPU":{"userSeconds":0.2,"systemSeconds":0.1}})
                BENCH.write_json(run/"server-cpu-before.json", {"userSeconds":1.0,"systemSeconds":2.0})
                BENCH.write_json(run/"server-cpu-after.json", {"userSeconds":1.2,"systemSeconds":2.1})
            BENCH.summarize(root)
            summary = json.loads((root/"summary.json").read_text(encoding="utf-8"))
            self.assertEqual(len(summary["runs"]),2)
            self.assertEqual(summary["groups"][0]["repetitions"],2)
            self.assertAlmostEqual(summary["groups"][0]["legitimateSuccessRatio"]["median"],0.95)
            self.assertEqual(summary["groups"][0]["legitimateP95Milliseconds"]["median"],4.0)
            self.assertIsNone(summary["runs"][1]["legitimateP95Milliseconds"])
            self.assertTrue((root/"summary.csv").is_file())

    def test_summary_rejects_reset_process_cpu(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);run=root/"run-001-nft-1";run.mkdir()
            BENCH.write_json(run/"run.json",{"mode":"nft","repetition":1})
            BENCH.write_json(run/"client.json",{"streams":{"legitimate":{"offeredPPS":1,"successRatio":1}},
                "legitimateRTT":{"p95Milliseconds":1},"clientProcessCPU":{"userSeconds":1,"systemSeconds":1}})
            BENCH.write_json(run/"server-cpu-before.json",{"userSeconds":2,"systemSeconds":2})
            BENCH.write_json(run/"server-cpu-after.json",{"userSeconds":1,"systemSeconds":1})
            with self.assertRaises(ValueError):BENCH.summarize(root)


if __name__ == "__main__":
    unittest.main()
