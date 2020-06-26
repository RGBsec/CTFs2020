/*
 * expohash.cpp
 *
 *  Created on: Jun 22, 2020
 *      Author: Stanley
 */

#include <fstream>
#include <iostream>
#include <algorithm>
#include <cassert>
#include <queue>
#include <set>
#include <string>
#include <vector>
#include <map>

using namespace std;

#define FI first
#define SE second
#define all(obj) begin(obj), end(obj)

typedef long long ll;
typedef pair<int,int> pii;
typedef pair<ll,ll> pll;
typedef vector<set<int> > vsi;
typedef unsigned long long ull;

string to_string(const char& c){return string(1, c);}
string to_string(const string& s){return '"'+s+'"';}
string to_string(const char* s){return to_string((string)s);}
string to_string(const bool& b){return (b?"true":"false");}
string to_string(const vector<bool>& v,const string& sep=" ") {
	string s = "[";
	for (int i=0; i<v.size(); i++) {if (i){s += sep;} s += to_string(v[i]);}
	return s + "]";
}
template <size_t N> string to_string(const bitset<N>& v) {
	string s = "[";
	for (size_t i=0; i<N; i++) s += v[i] ? '1' : '0';
	return s + "]";
}
template <class T1,class T2> string to_string(const pair<T1, T2>& p, const string& sep=",");
template <class T> string to_string(const T& v, const string& sep=" ") {
	bool first = true; string s = "{";
	for (const auto &x: v) {
		if (!first) s += sep;
		else first = false;
		s += to_string(x);
	}
	return s + "}";
}
template <class T> string to_string(const T& v, const int& sz, const string& sep=" ") {
	string s = "[";
	for (int i=0; i<sz; i++) {if (i){s += sep;} s += to_string(v[i]);}
	return s + "]";
}
template <class T1,class T2> string to_string(const pair<T1,T2>& p, const string& sep) {return "(" + to_string(p.first) + sep + to_string(p.second) + ")";}

#define debug(obj) cout << #obj << ": " << to_string(obj) << endl;
#define debug1(obj, sz) cout << #obj << ": " << to_string(obj, sz) << endl;
#define debug2(obj, sz1, sz2) cout << "-----" << #obj << "-----\n"; for (int i=0; i<sz1; i++) cout << to_string(obj[i], sz2) << " "; cout << endl;


template <class T> void chmn(T& a, const T& b) {if (a>b) a=b;}
template <class T> void chmx(T& a, const T& b) {if (a<b) a=b;}


struct Interval {
	int left, right;
	int val;

	void print() {
		cout << left << ' ' << right << ' ' << val << ' ' << endl;
	}
};
bool comp_left(const Interval &a, const Interval &b) {
	if (a.left == b.left) return a.right < b.right;
	return a.left < b.left;
}
bool comp_right(const Interval &a, const Interval &b) {
	if (a.right == b.right) return a.left < b.left;
	return a.right < b.right;
}
bool comp_size(const Interval &a, const Interval &b) {
	return (a.right - a.left) < (b.right - b.left);
}

const int N = 1e5;
const int M = 1e5;
const int MX = 1001001001;

void update(int tree[], int pos, int val) {
	pos += N;
	tree[pos] = val;

	while (pos > 1) {
		pos >>= 1;
		tree[pos] = tree[2 * pos] ^ tree[2 * pos + 1];
	}
}

int query(int tree[], int left, int right, bool mn) {
	left += N;
	right += N + 1;

	int ret = mn ? MX : 0;
	while (left < right) {
		if (left & 1) {
			if (mn) {
				chmn(ret, tree[left++]);
			}
			else {
				ret ^= tree[left++];
			}
		}
		if (right & 1) {
			if (mn) {
				chmn(ret, tree[--right]);
			}
			else {
				ret ^= tree[--right];
			}
		}
		left >>= 1;
		right >>= 1;
	}

	return ret;
}
int segtree[N * 2];
int msegtree[N * 2];
vector<Interval> vals;

struct comp_min_freq {
	inline const bool operator() (const int& a, const int& b) {
		return query(msegtree, vals[a].left, vals[a].right, true) < query(msegtree, vals[b].left, vals[b].right, true);
	}
};

int pass[N];

set<int> ch;
vector<int> used[N];
int by[N];
int freq[N];
set<int> istart[N+1], iend[N+1];
bool comp_freq(const int &a, const int &b) {
	return freq[a] < freq[b];
}

pii find_similar(int idx, int i, int j) {
	set<int> astart, aend;
	while (i >= 0 && j <= vals[idx].right) {
		aend.insert(all(iend[i]));
		for (set<int>::iterator it=istart[i].begin(); it!=istart[i].end(); it++) {
			set<int>::iterator it2 = aend.find(*it);
			if (it2 != aend.end()) {
				aend.erase(it2);
			}
			else {
				astart.insert(*it);
			}
		}
		while (j <= vals[idx].right && astart.size() > 0) {
			astart.insert(all(istart[j]));
			for (set<int>::iterator it=iend[j].begin(); it!=iend[j].end(); it++) {
				set<int>::iterator it2 = astart.find(*it);
				if (it2 != astart.end()) {
					astart.erase(it2);
				}
				else {
					aend.insert(*it);
				}
			}
			if (astart.size() > 0) ++j;
		}

		set<int>::iterator it1 = astart.begin();
		set<int>::iterator it2 = aend.begin();
		while (it1 != astart.end() && it2 != aend.end()) {
			if (*it1 == *it2) {
				it1 = astart.erase(it1);
				it2 = aend.erase(it2);
				debug(*it1);
			}
			else if (*it1 < *it2) {
				it1++;
			}
			else {
				it2++;
			}
		}

		if (j > vals[idx].right) break;

		if (astart.size() + aend.size() == 0) {
			return pii(i, j);
		}
		--i;
	}
	return pii(-1, -1);
}

int cb;

bool process(int idx) {
	cout << idx << ": " << query(segtree, vals[idx].left, vals[idx].right, false) << ' ';
	vals[idx].print();
	istart[vals[idx].left].insert(idx);
	iend[vals[idx].right + 1].insert(idx);


	set<int>::iterator ub = ch.upper_bound(vals[idx].right);
	for (set<int>::iterator it = ch.lower_bound(vals[idx].left); it != ub; ) {
		used[idx].push_back(*it);
		by[*it] = idx;
		it = ch.erase(it);
	}
	assert(used[idx].size() < 2);

	int diff = (vals[idx].val ^ query(segtree, vals[idx].left, vals[idx].right, false)) & (1LL << cb);
	if (diff == 0) {
		return true;
	}

	sort(used[idx].begin(), used[idx].end(), comp_freq);

	for (int i = 0; i < used[idx].size(); i++) {
		int cur = used[idx][i];

		pass[cur] ^= diff;
		update(segtree, cur, pass[cur]);
		return true;
	}

//	pii left_side = find_similar(idx, vals[idx].left - 1, vals[idx].left);
//	if (left_side.FI != -1) {
//		pass[left_side.FI] ^= diff;
//		pass[left_side.SE] ^= diff;
//		update(segtree, left_side.FI, pass[left_side.FI]);
//		update(segtree, left_side.SE, pass[left_side.SE]);
//		return true;
//	}
//	pii right_side = find_similar(idx, vals[idx].right, vals[idx].right + 1);
//	if (right_side.FI != -1) {
//		pass[right_side.FI] ^= diff;
//		pass[right_side.SE] ^= diff;
//		update(segtree, right_side.FI, pass[right_side.FI]);
//		update(segtree, right_side.SE, pass[right_side.SE]);
//		return true;
//	}

	cout << idx << endl;
	return false;

	return true;
}

int main() {
	freopen(string("example_input4.txt").c_str(), "r", stdin);
	fill(pass, pass + N, 0);
	fill(segtree, segtree + N + N, 0);
	fill(msegtree, msegtree + N + N, 0);

	vals = vector<Interval>(M);
	for (int i = 0; i < M; i++) {
		cin >> vals[i].left >> vals[i].right >> vals[i].val;
		vals[i].left--;
		vals[i].right--;
	}
	sort(vals.begin(), vals.end(), comp_left);
//	for (int i=0; i<M; i++) {
//		for (int j=0; j<M; j++) {
//			if (i == j) continue;
//			if (vals[i].left == vals[j].left) {
//				if (vals[i].right < vals[j].right) {
//					vals[j].left = vals[i].right + 1;
//					vals[j].val ^= vals[i].val;
//				}
//				else if (vals[i].right > vals[j].right) {
//					vals[i].left = vals[j].right + 1;
//					vals[i].val ^= vals[j].val;
//				}
//				else {
//					assert(false);
//				}
//			}
//			else if (vals[i].right == vals[j].right) {
//				if (vals[i].left < vals[j].left) {
//					vals[i].right = vals[j].left - 1;
//					vals[i].val ^= vals[j].val;
//				}
//				else if (vals[i].left > vals[j].left) {
//					vals[j].right = vals[i].left - 1;
//					vals[j].val ^= vals[i].val;
//				}
//				else {
//					assert(false);
//				}
//			}
//			else if (vals[i].right < vals[j].left) break;
//		}
//	}
	for (int i=0; i<M; i++) {
		istart[vals[i].left].insert(i);
		iend[vals[i].right + 1].insert(i);
	}

	set<int> active;
	for (int i = 0; i < N; i++) {
		ch.insert(i);
		for (set<int>::iterator it=istart[i].begin(); it!=istart[i].end(); it++) {
			active.insert(*it);
		}
		for (set<int>::iterator it=iend[i].begin(); it!=iend[i].end(); it++) {
			active.erase(*it);
		}
		freq[i] = active.size();
		update(msegtree, i, freq[i]);
	}

	for (cb=0; cb<32; cb++) {
		fill(istart, istart+N, set<int>());
		fill(iend, iend+N, set<int>());
		fill(used, used + N, vector<int>());

		sort(vals.begin(), vals.end(), comp_size);

		int bad = 0;
		priority_queue<int, vector<int>, comp_min_freq> pq;
		for (int i=0; i<N; i++) pq.push(i);
		while (pq.size() > 0) {
			int cur = pq.top();
			pq.pop();

			if (!process(cur)) {
				if (++bad > N) {
					break;
				}
				pq.push(cur);
			}
			else {
				bad = 0;
			}
		}
		if (pq.size() > 0) {
			return 0;
		}
	}


	for (int i=0; i<N; i++) {
		cout << pass[i] << endl;
	}
}
