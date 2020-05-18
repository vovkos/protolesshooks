#pragma once

#include "plh_Def.h"

namespace plh {

//..............................................................................

size_t
uleb128(
	const void* p,
	size_t size,
	uint64_t* result = NULL
	);

size_t
sleb128(
	const void* p,
	size_t size,
	int64_t* result = NULL
	);

//..............................................................................

} // namespace plh
