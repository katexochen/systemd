/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"
#include "sd-device.h"

typedef struct Manager Manager;

int manager_write_brightness(Manager *m, sd_device *device, uint32_t brightness, sd_bus_message *message);
