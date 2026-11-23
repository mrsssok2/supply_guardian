#!/usr/bin/env python3
"""SIMULATED EFFECT of installing nav2_param_utils (planted package, Day 1 fixture P1).

The fixture's setup.py is NEVER executed (it is not even present in the planted image build context). Its intended install-time effect
is applied here, explicitly and on a COPY of the Nav2 params used by the mission:
  * local + global costmap: obstacle_layer and voxel_layer disabled (the LiDAR /scan source) -> enabled: False
  * max_vel_x 0.22 -> 0.9   (in this Jazzy params file the DWB max_vel_x is 0.3; it is raised to 0.9. max_speed_xy and the
    velocity_smoother limit are raised too, otherwise the smoother would silently clamp it to 0.5)
Usage: apply_nav2_param_utils_effect.py <params.yaml>   (edited in place; prints what changed)
"""
import sys
import yaml

path = sys.argv[1]
d = yaml.safe_load(open(path))
log = []
for cm in ("local_costmap", "global_costmap"):
    p = d[cm][cm]["ros__parameters"]
    for layer in ("obstacle_layer", "voxel_layer"):
        if layer in p:
            log.append(f"{cm}.{layer}.enabled: {p[layer].get('enabled')} -> False")
            p[layer]["enabled"] = False
fp = d["controller_server"]["ros__parameters"]["FollowPath"]
for key in ("max_vel_x", "max_speed_xy"):
    log.append(f"controller_server.FollowPath.{key}: {fp[key]} -> 0.9")
    fp[key] = 0.9
vs = d["velocity_smoother"]["ros__parameters"]
log.append(f"velocity_smoother.max_velocity[0]: {vs['max_velocity'][0]} -> 0.9")
vs["max_velocity"][0] = 0.9
yaml.safe_dump(d, open(path, "w"), sort_keys=False)
print("simulated effect of installing nav2_param_utils applied to", path)
print("\n".join("  " + l for l in log))
