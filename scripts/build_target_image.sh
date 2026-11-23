#!/usr/bin/env bash
# Build tb3-target:<label> from a branch of target/ using colcon INSIDE a container from the local gurdy2/ros:jazzy image.
# Usage: scripts/build_target_image.sh main main | scripts/build_target_image.sh planted planted
# planted: nav2_param_utils / rclpy_utils are removed from the build context (their setup.py must NEVER run) and the intended
# install-time effect is applied as a separate, labelled step on the Nav2 params copy.
set -euo pipefail
LABEL=$1; BRANCH=$2
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CTX=$ROOT/out/build/$LABEL
rm -rf "$CTX"; mkdir -p "$CTX"
git -C "$ROOT/target" archive "$BRANCH" robot_ws | tar -x -C "$CTX"
for bad in nav2_param_utils rclpy_utils; do rm -rf "$CTX/robot_ws/src/$bad"; done      # never built, never executed
cp "$ROOT/scripts/mission/apply_nav2_param_utils_effect.py" "$CTX/"
{
cat <<'EOF'
FROM gurdy2/ros:jazzy
USER root
ENV TURTLEBOT3_MODEL=burger
COPY robot_ws /robot_ws
WORKDIR /robot_ws
# build only what the Gazebo mission needs (turtlebot3_node needs real-hardware drivers that are not in the image)
RUN bash -c "source /opt/ros/jazzy/setup.bash && colcon build --packages-up-to turtlebot3_gazebo turtlebot3_navigation2 turtlebot3_description turtlebot3_msgs --event-handlers console_cohesion+"
RUN mkdir -p /mission_params && cp /robot_ws/install/turtlebot3_navigation2/share/turtlebot3_navigation2/param/burger.yaml /mission_params/nav2_params.yaml
# proof that the fixture setup.py never ran: its output file must not exist anywhere
RUN test -z "$(find / -name burger_local_copy.yaml -not -path '/proc/*' 2>/dev/null)"
EOF
if [ "$BRANCH" = planted ]; then cat <<'EOF'
COPY apply_nav2_param_utils_effect.py /tmp/apply_effect.py
# ===== simulated effect of installing nav2_param_utils (setup.py is NOT executed) =====
RUN python3 /tmp/apply_effect.py /mission_params/nav2_params.yaml
EOF
fi
} > "$CTX/Dockerfile"
docker build -t "tb3-target:$LABEL" "$CTX" 2>&1 | tail -${BUILD_TAIL:-25}
docker image inspect "tb3-target:$LABEL" --format 'built tb3-target:{{index .RepoTags 0}} {{.Size}} bytes' | head -1
