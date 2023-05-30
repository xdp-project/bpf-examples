/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LHIST_H
#define LHIST_H

#include <stdlib.h>
#include <math.h>
#include <linux/types.h>

#include <stdio.h>

/* Count total number of instances in histogram*/
static __u64 lhist_count(__u32 *bins, size_t size)
{
	__u64 count = 0;
	int i;
	for (i = 0; i < size; i++)
		count += bins[i];
	return count;
}

static double lhist_bin_midval(int bin_idx, double bin_width, double left_edge)
{
	return left_edge + (bin_width / 2) + bin_width * bin_idx;
}

/* Calculate an approximate minimum value from a linear histogram.
 * The approximation is the middle of the first non-empty bin. */
static double lhist_min(__u32 *bins, size_t size, double bin_width,
			double left_edge)
{
	int i;

	for (i = 0; i < size; i++) {
		if (bins[i] > 0)
			break;
	}

	return size < 1 || bins[i] == 0 ?
		       NAN :
		       lhist_bin_midval(i, bin_width, left_edge);
}

/* Calculate an approximate maximum value from a linear histogram.
 * The approximation is the middle of the last non-empty bin. */
static double lhist_max(__u32 *bins, size_t size, double bin_width,
			double left_edge)
{
	int i, last_nonempty = 0;

	for (i = 0; i < size; i++) {
		if (bins[i] > 0)
			last_nonempty = i;
	}

	return size < 1 || bins[last_nonempty] == 0 ?
		       NAN :
		       lhist_bin_midval(last_nonempty, bin_width, left_edge);
}

/* Calculate an apporximate arithmetic mean from a linear histogram.
 * The approximation is based on the assumption that all instances are located
 * in the middle of their respective bins. */
static double lhist_mean(__u32 *bins, size_t size, double bin_width,
			 double left_edge)
{
	double sum = 0, mid_val = left_edge + (bin_width / 2);
	__u64 count = 0;
	int i;

	for (i = 0; i < size; i++) {
		count += bins[i];
		sum += bins[i] * mid_val;
		mid_val += bin_width;
	}

	return count ? sum / count : NAN;
}

/* Calculate an approximate percentile value from a linear histogram.
 * The approximation is based on the assumption that all instances are located
 * in the middle of their respective bins. Does linear interpolation for
 * percentiles located between bins (similar to ex. numpy.percentile) */
static double lhist_percentile(__u32 *bins, double percentile, size_t size,
			       double bin_width, double left_edge)
{
	__u64 n = lhist_count(bins, size);
	double virt_idx, ret;
	int i = 0, next_i;
	__u64 count = 0;

	if (n < 1)
		return NAN;

	virt_idx = percentile / 100 * (n - 1);

	/* Check for out of bounds percentiles or rounding errors*/
	if (virt_idx <= 0)
		return lhist_min(bins, size, bin_width, left_edge);
	else if (virt_idx >= n - 1)
		return lhist_max(bins, size, bin_width, left_edge);

	/* find bin the virtual index should lie in */
	while (count <= virt_idx) {
		count += bins[i++];
	}
	i--;
	ret = lhist_bin_midval(i, bin_width, left_edge);

	/* virtual index is between current bin and next (non-empty) bin
	   (count - 1 < virt_idx < count) */
	if (virt_idx > count - 1) {
		/* Find next non-empty bin to interpolate between */
		next_i = i + 1;
		while (bins[next_i] == 0) {
			next_i++;
		}
		ret += (virt_idx - (count - 1)) * (next_i - i) * bin_width;
	}
	return ret;
}

#endif
