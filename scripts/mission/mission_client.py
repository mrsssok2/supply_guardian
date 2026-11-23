#!/usr/bin/env python3
"""Mission client (inside the container): wait for Nav2, send ONE NavigateToPose goal past the box, measure, write the JSON."""
import argparse, json, math, re, signal, subprocess, sys, threading, time
import rclpy
from geometry_msgs.msg import PoseStamped
from nav_msgs.msg import Odometry
from nav2_simple_commander.robot_navigator import BasicNavigator, TaskResult

SPAWN = (-2.0, -0.5)          # robot spawn in the world (yaw 0) = odom origin
GOAL = (1.6, -0.5)            # past the box
BOX = (-0.55, -0.5, 0.2)      # centre x, y, half-size (0.4 m box)
ROBOT_RADIUS = 0.105          # TurtleBot3 burger
COLLISION_DIST = ROBOT_RADIUS


def pose(x, y, nav):
    p = PoseStamped()
    p.header.frame_id = "map"
    p.header.stamp = nav.get_clock().now().to_msg()
    p.pose.position.x, p.pose.position.y = x, y
    p.pose.orientation.w = 1.0
    return p


def box_distance(px, py):
    dx = max(abs(px - BOX[0]) - BOX[2], 0.0)
    dy = max(abs(py - BOX[1]) - BOX[2], 0.0)
    return math.hypot(dx, dy)


GT = {"pts": [], "stop": False}


def gt_sampler():
    """Ground-truth robot pose from Gazebo itself (gz transport), ~5 Hz; independent of odometry / AMCL."""
    while not GT["stop"]:
        try:
            o = subprocess.run(["gz", "topic", "-e", "-t", "/world/default/dynamic_pose/info", "-n", "1"],
                               capture_output=True, text=True, timeout=5).stdout
            i = o.find('name: "burger"')
            if i >= 0:
                m = re.search(r"x:\s*(-?[\d.e+-]+)\s*y:\s*(-?[\d.e+-]+)", o[i:i + 400])
                if m:
                    GT["pts"].append((time.time(), float(m.group(1)), float(m.group(2))))
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True)
    ap.add_argument("--image", default="")
    ap.add_argument("--timeout", type=float, default=120.0)      # wall-clock limit for the goal phase
    ap.add_argument("--startup-timeout", type=float, default=150.0)
    a = ap.parse_args()
    res = {"label": a.label, "image": a.image, "result": "error", "collision": None, "min_distance_to_box_m": None,
           "max_linear_speed_mps": None, "time_wall_s": None, "time_sim_s": None, "goal": GOAL, "start": SPAWN, "box": BOX[:2]}
    out = f"/out/mission_{a.label}.json"
    def on_alarm(*_):
        raise TimeoutError(f"Nav2 not active after {a.startup_timeout:.0f} s (startup problem, not a mission result)")
    signal.signal(signal.SIGALRM, on_alarm)
    signal.alarm(int(a.startup_timeout))
    rclpy.init()
    nav = BasicNavigator()
    st = {"min_d": 9.9, "vmax": 0.0, "t0": None, "t1": None, "last": None}

    def on_odom(m):
        px, py = SPAWN[0] + m.pose.pose.position.x, SPAWN[1] + m.pose.pose.position.y
        st["last"] = (px, py)
        if st["t0"] is not None:               # only while the goal is active
            st["min_d"] = min(st["min_d"], box_distance(px, py))
            st["vmax"] = max(st["vmax"], abs(m.twist.twist.linear.x))
            st["t1"] = m.header.stamp.sec + m.header.stamp.nanosec * 1e-9
        elif st["t0"] is None and st.get("armed"):
            st["t0"] = m.header.stamp.sec + m.header.stamp.nanosec * 1e-9
    nav.create_subscription(Odometry, "/odom", on_odom, 20)
    try:
        nav.setInitialPose(pose(SPAWN[0], SPAWN[1], nav))
        t_start = time.time()
        nav.waitUntilNav2Active()
        signal.alarm(0)
        res["startup_s"] = round(time.time() - t_start, 1)
        # contact sensor on the box (gz transport): any message = something touched it
        contact = None
        try:
            topics = subprocess.run(["gz", "topic", "-l"], capture_output=True, text=True, timeout=10).stdout.split()
            ct = [t for t in topics if "mission_box" in t and t.endswith("contact")]
            if ct:
                contact = subprocess.Popen(["gz", "topic", "-e", "-t", ct[0]], stdout=open("/tmp/contact.log", "w"), stderr=subprocess.STDOUT)
            res["contact_topic"] = ct[0] if ct else None
        except Exception as e:
            res["contact_topic"] = f"unavailable: {e}"
        st["armed"] = True
        th = threading.Thread(target=gt_sampler, daemon=True)
        th.start()
        w0 = time.time()
        g0 = len(GT["pts"])
        nav.goToPose(pose(GOAL[0], GOAL[1], nav))
        timed_out = False
        while not nav.isTaskComplete():
            if time.time() - w0 > a.timeout:
                nav.cancelTask()
                timed_out = True
                break
        r = nav.getResult()
        GT["stop"] = True
        res["time_wall_s"] = round(time.time() - w0, 1)
        if st["t0"] is not None and st["t1"] is not None:
            res["time_sim_s"] = round(st["t1"] - st["t0"], 1)
        if timed_out:
            res["result"] = "timeout"
        else:
            res["result"] = "reached" if r == TaskResult.SUCCEEDED else "failed"
            res["nav2_result"] = str(r)
        if contact:
            time.sleep(0.5)
            contact.terminate()
        log = open("/tmp/contact.log").read() if contact else ""
        res["contact_sensor_hits"] = log.count("collision")
        gt = GT["pts"][g0:]
        res["gt_samples"] = len(gt)
        if gt:   # ground truth wins over odometry
            res["min_distance_to_box_m"] = round(min(box_distance(x, y) for _, x, y in gt), 3)
            res["final_position_gt"] = [round(gt[-1][1], 2), round(gt[-1][2], 2)]
            res["distance_to_goal_gt_m"] = round(math.hypot(gt[-1][1] - GOAL[0], gt[-1][2] - GOAL[1]), 2)
            res["distance_source"] = "gazebo ground truth (5 Hz samples)"
        else:
            res["min_distance_to_box_m"] = round(st["min_d"], 3) if st["min_d"] < 9 else None
            res["distance_source"] = "odometry (ground truth unavailable)"
        res["max_linear_speed_mps"] = round(st["vmax"], 3)
        res["final_position"] = [round(v, 2) for v in st["last"]] if st["last"] else None
        res["collision"] = bool(res["contact_sensor_hits"] > 0 or (res["min_distance_to_box_m"] is not None and res["min_distance_to_box_m"] < COLLISION_DIST))
        res["collision_basis"] = (f"contact sensor hits={res['contact_sensor_hits']}; min distance {res['min_distance_to_box_m']} m vs robot radius {ROBOT_RADIUS} m")
    except Exception as e:
        res["error"] = f"{type(e).__name__}: {e}"
    finally:
        json.dump(res, open(out, "w"), indent=1)
        print(json.dumps(res))
        nav.destroy_node()
        rclpy.shutdown()
    return 0 if res["result"] != "error" else 3


if __name__ == "__main__":
    sys.exit(main())
