#!/usr/bin/env python3
"""Mission test: launch Gazebo (headless; GUI=true for the demo video via WSLg) + Nav2, send ONE NavigateToPose goal past the box.
Usage: scripts/mission_test.py --image tb3-target:main --label main_1
Prints PASS/FAIL, saves out/mission_<label>.json. PASS = goal reached AND no collision with the box. Wall-clock limit for the goal: 120 s.
Everything runs in one throw-away container with --network none; the container is always removed on exit (also on Ctrl-C / timeout)."""
import argparse, atexit, json, os, signal, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "out"


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--timeout", type=int, default=120, help="wall-clock limit of the navigation goal (s)")
    ap.add_argument("--attempts", type=int, default=2, help="restarts if Nav2 never comes up (infrastructure flake, not a mission result)")
    a = ap.parse_args()
    OUT.mkdir(exist_ok=True)
    busy = [l for l in sh(["docker", "ps", "--format", "{{.Names}} {{.Image}}"]).stdout.splitlines() if "gurdy" in l.lower()]
    if busy:
        sys.exit(f"refusing to run while a gurdy2 container is up: {busy}")
    name = f"tb3mission_{a.label}"
    gui = os.environ.get("GUI", "false").lower() == "true"

    def cleanup():
        sh(["docker", "rm", "-f", name])
    atexit.register(cleanup)
    for s in (signal.SIGINT, signal.SIGTERM):
        signal.signal(s, lambda *_: (cleanup(), sys.exit(130)))
    result = None
    for attempt in range(1, a.attempts + 1):
        cleanup()
        (OUT / f"mission_{a.label}.json").unlink(missing_ok=True)
        cmd = ["docker", "run", "--rm", "--name", name, "--user", f"{os.getuid()}:{os.getgid()}", "--entrypoint", "bash",
               "-v", f"{ROOT / 'scripts' / 'mission'}:/mission:ro", "-v", f"{OUT}:/out", "-e", f"GUI={'true' if gui else 'false'}",
               "-e", f"MISSION_TIMEOUT={a.timeout}"]
        if gui:   # WSLg
            cmd += ["-v", "/tmp/.X11-unix:/tmp/.X11-unix", "-v", "/mnt/wslg:/mnt/wslg", "-e", f"DISPLAY={os.environ.get('DISPLAY', ':0')}",
                    "-e", "WAYLAND_DISPLAY=wayland-0", "-e", "XDG_RUNTIME_DIR=/mnt/wslg/runtime-dir", "-e", "LIBGL_ALWAYS_SOFTWARE=1"]
            if os.path.exists("/dev/dxg"):
                cmd += ["--device", "/dev/dxg", "-v", "/usr/lib/wsl:/usr/lib/wsl", "-e", "LD_LIBRARY_PATH=/usr/lib/wsl/lib"]
        else:
            cmd += ["--network", "none"]
        cmd += [a.image, "/mission/in_container.sh", a.label, a.image]
        t0 = time.time()
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=a.timeout + a.attempts * 0 + 330)
            rc = p.returncode
        except subprocess.TimeoutExpired:
            rc = 124
        print(f"[{a.label}] attempt {attempt}: container exit {rc} after {time.time() - t0:.0f} s wall")
        f = OUT / f"mission_{a.label}.json"
        result = json.loads(f.read_text()) if f.exists() else None
        if result and result.get("result") != "error":
            break
        print(f"[{a.label}] no mission result (startup problem: {(result or {}).get('error', 'no json')}); see out/launch_{a.label}.log")
    cleanup()
    if not result or result.get("result") == "error":
        print(f"ERROR {a.label}: Nav2/Gazebo did not start; no PASS/FAIL")
        return 2
    verdict = "PASS" if result["result"] == "reached" and not result["collision"] else "FAIL"
    result["verdict"] = verdict
    result["gui"] = gui
    (OUT / f"mission_{a.label}.json").write_text(json.dumps(result, indent=1))
    print(f"{verdict} {a.label}: result={result['result']} collision={result['collision']} min_dist={result['min_distance_to_box_m']} m "
          f"max_speed={result['max_linear_speed_mps']} m/s time={result['time_wall_s']} s wall / {result['time_sim_s']} s sim")
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
