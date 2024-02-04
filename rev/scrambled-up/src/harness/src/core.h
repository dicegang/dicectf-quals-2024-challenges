#pragma once

#include <inttypes.h>
#include <stddef.h>
#include <stdlib.h>

#include "modules/interface.h"
#include "util.h"

#define create_value_string_from_literal(str) create_value_string((uint8_t *) str, sizeof(str))
