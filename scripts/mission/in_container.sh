#!/usr/bin/env bash
# Runs INSIDE the container: launch Gazebo+Nav2 in the background, run the mission client, clean up.
LABEL=$1; IMAGE=$2
source /opt/ros/jazzy/setup.bash; source /robot_ws/install/setup.bash
export TURTLEBOT3_MODEL=burger HOME=/tmp/home ROS_LOG_DIR=/tmp/roslog GZ_IP=127.0.0.1 ROS_DOMAIN_ID=${ROS_DOMAIN_ID:-77}
mkdir -p "$HOME" "$ROS_LOG_DIR"
ros2 launch /mission/mission_launch.py > /out/launch_$LABEL.log 2>&1 &
LAUNCH=$!
python3 /mission/mission_client.py --label "$LABEL" --image "$IMAGE" --timeout "${MISSION_TIMEOUT:-120}" --startup-timeout "${STARTUP_TIMEOUT:-150}"
RC=$?
kill -TERM $LAUNCH 2>/dev/null; sleep 3; pkill -KILL -f "gz sim|parameter_bridge|component_container|nav2|robot_state_publisher" 2>/dev/null
exit $RC
