#pragma once
#ifndef ANALYSE_H
#define ANALYSE_H

struct metric {
	bstring name;
	bstring filterprogram;
	long long bytes;
	struct bpf_program compiledfilter;
};


struct metrics {
	struct metric *metrics;
	int bufferlen;
	int count;
};

#endif