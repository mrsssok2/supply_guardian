#!/usr/bin/env bash
# Positive control for the measurement instruments: drive the robot straight into the box (no Nav2) and check that the contact sensor
# and the ground-truth distance both register it. Runs inside the container.
source /opt/ros/jazzy/setup.bash; source /robot_ws/install/setup.bash
export TURTLEBOT3_MODEL=burger HOME=/tmp/home ROS_LOG_DIR=/tmp/roslog GZ_IP=127.0.0.1 ROS_DOMAIN_ID=78
mkdir -p $HOME $ROS_LOG_DIR
ros2 launch /mission/mission_launch.py > /tmp/pc_launch.log 2>&1 &
until ros2 topic list 2>/dev/null | grep -q "^/scan$"; do sleep 2; done; sleep 8
CT=$(gz topic -l | grep "mission_box.*contact$" | head -1); echo "contact topic: $CT"
gz topic -e -t "$CT" > /tmp/contact.log 2>&1 &
( for i in $(seq 1 140); do gz topic -e -t /world/default/dynamic_pose/info -n 1 2>/dev/null | grep -A5 'name: "burger"' | grep -E "^\s+(x|y):" | tr -d ' \n'; echo; sleep 0.1; done ) > /tmp/gt.log &
timeout 14 ros2 topic pub -r 10 /cmd_vel geometry_msgs/msg/TwistStamped "{header: {frame_id: base_link}, twist: {linear: {x: 0.3}}}" > /dev/null 2>&1
sleep 2
echo "contact sensor 'collision' mentions: $(grep -c collision /tmp/contact.log)"
python3 - <<'PY'
import re, math
pts = []
for l in open('/tmp/gt.log'):
    m = re.match(r'x:(-?[\d.e+-]+)y:(-?[\d.e+-]+)', l.strip())
    if m: pts.append((float(m.group(1)), float(m.group(2))))
d = lambda x, y: math.hypot(max(abs(x + 0.55) - 0.2, 0), max(abs(y + 0.5) - 0.2, 0))
print("ground-truth samples:", len(pts), "min distance to box:", round(min(d(*p) for p in pts), 3), "final x,y:", pts[-1])
PY
pkill -KILL -f "gz sim|parameter_bridge|component_container|nav2|robot_state_publisher|ros2 launch" 2>/dev/null
