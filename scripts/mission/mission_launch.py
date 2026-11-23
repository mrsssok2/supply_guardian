"""Gazebo (mission world: TurtleBot3 world + ONE box) + TurtleBot3 burger + Nav2 with the image's params. Runs inside the container."""
import os
from ament_index_python.packages import get_package_share_directory as share
from launch import LaunchDescription
from launch.actions import AppendEnvironmentVariable, IncludeLaunchDescription
from launch.launch_description_sources import PythonLaunchDescriptionSource as PY


def generate_launch_description():
    tb3, ros_gz, nav2 = share("turtlebot3_gazebo"), share("ros_gz_sim"), share("nav2_bringup")
    gui = os.environ.get("GUI", "false").lower() == "true"
    params = os.environ.get("NAV2_PARAMS", "/mission_params/nav2_params.yaml")
    map_yaml = os.path.join(share("turtlebot3_navigation2"), "map", "map.yaml")     # static map: pillars + walls, NO box
    world = "/mission/mission_world.sdf"
    gz_args = f"-r -v2 {world}" + ("" if gui else " -s --headless-rendering")
    return LaunchDescription([
        AppendEnvironmentVariable("GZ_SIM_RESOURCE_PATH", os.path.join(tb3, "models")),
        IncludeLaunchDescription(PY(os.path.join(ros_gz, "launch", "gz_sim.launch.py")),
                                 launch_arguments={"gz_args": gz_args, "on_exit_shutdown": "true"}.items()),
        IncludeLaunchDescription(PY(os.path.join(tb3, "launch", "robot_state_publisher.launch.py")),
                                 launch_arguments={"use_sim_time": "true"}.items()),
        IncludeLaunchDescription(PY(os.path.join(tb3, "launch", "spawn_turtlebot3.launch.py")),
                                 launch_arguments={"x_pose": "-2.0", "y_pose": "-0.5"}.items()),
        IncludeLaunchDescription(PY(os.path.join(nav2, "launch", "bringup_launch.py")),
                                 launch_arguments={"map": map_yaml, "params_file": params, "use_sim_time": "true", "autostart": "true"}.items()),
    ])
