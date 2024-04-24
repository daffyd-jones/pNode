import numpy as np
import math
import random
import pygame

def repulsive_force(distance, constant):
    return constant ** 2 / distance

def attractive_force(distance, constant):
    return distance ** 2 / constant

def distance_between_points(p1, p2):
    return math.sqrt((p1[0] - p2[0]) ** 2 + (p1[1] - p2[1]) ** 2)


def add_jitter(force, magnitude=5.51):
    jitter_x = (np.random.rand() - 0.5) * magnitude
    jitter_y = (np.random.rand() - 0.5) * magnitude
    return force[0] + jitter_x, force[1] + jitter_y

def resolve_overlaps(positions, min_distance=0.2):
    for node1 in positions.keys():
        for node2 in positions.keys():
            if node1 != node2:
                dx, dy = positions[node1][0] - positions[node2][0], positions[node1][1] - positions[node2][1]
                dist = math.sqrt(dx**2 + dy**2)
                if dist < min_distance:
                    adjust_x = (min_distance - dist) * (dx / dist if dist != 0 else 0)
                    adjust_y = (min_distance - dist) * (dy / dist if dist != 0 else 0)
                    positions[node1] = (positions[node1][0] + adjust_x / 2, positions[node1][1] + adjust_y / 2)
                    positions[node2] = (positions[node2][0] - adjust_x / 2, positions[node2][1] - adjust_y / 2)
    return positions


def create_connection_rect(color, node1, node2, width):
    dx = node2[0] - node1[0]
    dy = node2[1] - node1[1]
    length = math.sqrt(dx**2 + dy**2)

    angle = math.degrees(math.atan2(dy, dx))
    rect_surface = pygame.Surface((length, width), pygame.SRCALPHA)
    rect_surface.fill(color)
    rotated_surface = pygame.transform.rotate(rect_surface, -angle)

    if dx >= 0:
        center_x = node1[0] + dx / 2
        center_y = node1[1] + dy / 2
    else:
        center_x = node2[0] - dx / 2
        center_y = node2[1] - dy / 2

    collision_rect = rotated_surface.get_rect(center=(center_x, center_y))
    return rotated_surface, collision_rect

def is_point_on_line(surface, rect, point):
    if rect.collidepoint(point):
        local_point = (point[0] - rect.x, point[1] - rect.y)
        return surface.get_at(local_point)[3] != 0
    return False


def update_positions(nodes, positions, edges, repulsive_const, attractive_const, global_attractive_const, max_iterations=1000, max_displacement=0.1):
    center_x, center_y = 0, 0
    for _ in range(max_iterations):
        force = {node: (0, 0) for node in nodes}
        max_displacement = 0.1
        for i, node1 in enumerate(nodes):
            for node2 in nodes[i+1:]:
                dist = distance_between_points(positions[node1], positions[node2])
                if dist == 0:
                    continue
                repulsive = repulsive_force(dist, repulsive_const)
                dx, dy = positions[node1][0] - positions[node2][0], positions[node1][1] - positions[node2][1]
                force[node1] = (force[node1][0] + repulsive * dx / dist, force[node1][1] + repulsive * dy / dist)
                force[node2] = (force[node2][0] - repulsive * dx / dist, force[node2][1] - repulsive * dy / dist)

        for node1, node2 in edges:
            dist = distance_between_points(positions[node1], positions[node2])
            if dist == 0:
                positions[node2] = (positions[node2][0] + 0.6, positions[node2][1] + 0.6)
                dist = distance_between_points(positions[node1], positions[node2])
            attractive = attractive_force(dist, attractive_const)
            dx, dy = positions[node1][0] - positions[node2][0], positions[node1][1] - positions[node2][1]
            force[node1] = (force[node1][0] - attractive * dx / dist, force[node1][1] - attractive * dy / dist)
            force[node2] = (force[node2][0] + attractive * dx / dist, force[node2][1] + attractive * dy / dist)

        for node in nodes:
            dx = center_x - positions[node][0]
            dy = center_y - positions[node][1]
            distance = distance_between_points(positions[node], (center_x, center_y))
            if distance > 0:
                attract_force = global_attractive_const * distance
                force[node] = (force[node][0] + attract_force * dx / distance,
                               force[node][1] + attract_force * dy / distance)

        for node in nodes:
            disp_x, disp_y = force[node]
            disp_x += (np.random.rand() - 0.5) * 0.2
            disp_y += (np.random.rand() - 0.5) * 0.2

            disp_x = max(-max_displacement, min(max_displacement, disp_x))
            disp_y = max(-max_displacement, min(max_displacement, disp_y))

            pos_x, pos_y = positions[node]
            new_x, new_y = pos_x + disp_x, pos_y + disp_y

            if np.isfinite(new_x) and np.isfinite(new_y):
                positions[node] = (new_x, new_y)
            else:
                positions[node] = (pos_x, pos_y)

    positions = resolve_overlaps(positions, min_distance=0.5)
    return positions
