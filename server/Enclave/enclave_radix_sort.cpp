// Original code by Erik Gorset: https://github.com/gorset/radix/blob/master/radix.cc
// Modified for Intel SGX using uint32_t by Can Kockan
void insertion_sort(uint32_t* array, int offset, int end)
{
	int x;
	int y;
	int temp;

	for(x = offset; x < end; ++x)
	{
		for(y = x; y > offset && array[y - 1] > array[y]; y--)
		{
			temp = array[y];
			array[y] = array[y - 1];
			array[y - 1] = temp;
		}
	}
}

void radix_sort(uint32_t* array, int offset, int end, int shift)
{
	int x;
	int y;
	int value;
	int temp;
	int last[256] = {0};
	int pointer[256];

	for(x = offset; x < end; ++x)
	{
		++last[(array[x] >> shift) & 0xFF];
	}

	last[0] += offset;
	pointer[0] = offset;
	for(x = 1; x < 256; ++x)
	{
		pointer[x] = last[x - 1];
		last[x] += last[x - 1];
	}

	for(x = 0; x < 256; ++x)
	{
		while(pointer[x] != last[x])
		{
			value = array[pointer[x]];
			y = (value >> shift) & 0xFF;
			while(x != y)
			{
				temp = array[pointer[y]];
				array[pointer[y]++] = value;
				value = temp;
				y = (value >> shift) & 0xFF;
			}
			array[pointer[x]++] = value;
		}
	}

	if(shift > 0)
	{
		shift -= 8;
		for(x = 0; x < 256; ++x)
		{
			temp = x > 0 ? pointer[x] - pointer[x - 1] : pointer[0] - offset;
			if(temp > 64)
			{
				radix_sort(array, pointer[x] - temp, pointer[x], shift);
			}
			else if(temp > 1)
			{
				insertion_sort(array, pointer[x] - temp, pointer[x]);
			}
		}
	}
}
