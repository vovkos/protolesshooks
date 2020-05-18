#include "plh_Leb128.h"

// C-adaptation of the pseudo-code at https://en.wikipedia.org/wiki/LEB128

namespace plh {

//..............................................................................

size_t
uleb128(
	const void* p0,
	size_t size,
	uint64_t* result0
	)
{
	const uint8_t* p = (uint8_t*)p0;
	size_t i = 0;
	uint64_t result = 0;
	int shift = 0;

	while (i < size)
	{
		uint8_t byte = p[i++];
		result |= (uint64_t)(byte & 0x7f) << shift;
		if (!(byte & 0x80))
			break;

		shift += 7;
	}

	if (result0)
		*result0 = result;

	return i;
}

size_t
sleb128(
	const void* p0,
	size_t size,
	int64_t* result0
	)
{
	const uint8_t* p = (uint8_t*)p0;
	size_t i = 0;
	uint64_t result = 0;
	int shift = 0;

	while (i < size)
	{
		uint8_t byte = p[i++];
		result |= (uint64_t)(byte & 0x7f) << shift;
		shift += 7;

		if (!(byte & 0x80))
		{
			if (shift < 64 && (byte & 0x40))
				result |= (~0 << shift);

			break;
		}
	}

	if (result0)
		*result0 = result;

	return i;
}

//..............................................................................

} // namespace plh
