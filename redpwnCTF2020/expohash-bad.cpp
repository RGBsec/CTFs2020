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
#include <deque>
#include <cctype>
#include <climits>
#include <cmath>
#include <cstdlib>
#include <iomanip>
#include <utility>
#include <bitset>
#include <forward_list>
#include <list>
#include <stack>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

using namespace std;

#define PF push_front
#define PB push_back
#define INS insert

#define FI first
#define SE second
#define all(obj) begin(obj), end(obj)
#define rall(obj) (obj).rbegin(), (obj).rend()

#define LB lower_bound
#define UB upper_bound

typedef long long ll;
typedef pair<int,int> pii;
typedef pair<ll,ll> pll;
typedef vector<set<int> > vsi;

typedef unsigned long long ull;
typedef pair<int,bool> pib;
typedef pair<ll,bool> plb;
typedef vector<vector<int> > vvi;
typedef vector<set<pii> > vspi;
typedef vector<vector<pii> > vvpi;
typedef map<int,int> mii;
typedef map<ll,ll> mll;
typedef map<char, int> mci;
typedef map<string,int> msi;
typedef map<string,string> mss;

ll gcd(ll a, ll b) {return b ? gcd(b, a%b) : a;}

template <class T1,class T2> struct cmpf {
	bool rev;
	inline bool operator()(const pair<T1,T2>& a, const pair<T1,T2>& b) const {return (a.first<b.first)^rev;}
	cmpf(bool b=false) {rev=b;}
};
template <class T1,class T2> struct cmps {
	bool rev;
	inline bool operator()(const pair<T1,T2>& a, const pair<T1,T2>& b) const {return (a.second<b.second)^rev;}
	cmps(bool b=false) {rev=b;}
};

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
#define debug3(obj, sz1, sz2, sz3) cout << "-----" << #obj << "-----\n"; for (int i=0; i<sz1; i++) {for (int j=0; j<sz2; j++) cout << to_string(obj[i][j], sz3) << " "; cout << endl;} cout << endl;

ll binpow(const ll& x, const ll& p, const ll& mod) {assert(mod>0);
	if (p == 0) return 1;
	if (p == 1) return x % mod;
	if (p & 1) return (binpow((x*x) % mod, p/2, mod) * x) % mod;
	return binpow((x*x) % mod, p/2, mod) % mod;
}

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

int segtree[N * 2];
void update(int pos, int val) {
	pos += N;
	segtree[pos] = val;

	while (pos > 1) {
		pos >>= 1;
		segtree[pos] = segtree[2 * pos] ^ segtree[2 * pos + 1];
	}
}

int query(int left, int right) {
	left += N;
	right += N + 1;

	int ret = 0;
	while (left < right) {
		if (left & 1) {
			ret ^= segtree[left++];
		}
		if (right & 1) {
			ret ^= segtree[--right];
		}
		left >>= 1;
		right >>= 1;
	}

	return ret;
}

const int MX = 1001001001;

int pass[N];
vector<Interval> vals;

set<int> ch;
vector<int> used[N];
int by[N];
int freq[N];
int istart[N], iend[N];
bool comp_freq(const int &a, const int &b) {
	return freq[a] < freq[b];
}

int max_reached = 0;
bool recurse(int idx) {
	cout << idx << ": " << query(vals[idx].left, vals[idx].right) << ' ';
	vals[idx].print();
	if (idx == vals.size()) {
		return true;
	}
	istart[vals[idx].left]++;
	iend[vals[idx].right + 1]++;
	max_reached = max(max_reached, idx);
//	cout << max_reached << endl;
	if (idx == 2289) {
		return true;
	}


	set<int>::iterator ub = ch.upper_bound(vals[idx].right);
	for (set<int>::iterator it = ch.lower_bound(vals[idx].left); it != ub; ) {
		used[idx].push_back(*it);
		by[*it] = idx;
		assert(pass[*it] == 0);
		it = ch.erase(it);
	}

	int diff = vals[idx].val ^ query(vals[idx].left, vals[idx].right);
	if (diff == 0) {
		if (recurse(idx + 1)) {
			return true;
		}
	}

	sort(used[idx].begin(), used[idx].end(), comp_freq);

	for (int i = 0; i < used[idx].size(); i++) {
		int cur = used[idx][i];

		pass[cur] = diff;
		update(cur, diff);
		cout << "cur: " << cur << endl;
		if (recurse(idx + 1)) {
			return true;
		}
		pass[cur] = 0;
		update(cur, 0);
	}

	if (vals[idx].left > 0
			&& pass[vals[idx].left - 1] == 0 && pass[vals[idx].left] == 0
			&& istart[vals[idx].left] == 1 && iend[vals[idx].left] == 0) {

		pass[vals[idx].left - 1] = pass[vals[idx].left] = diff;
		update(vals[idx].left - 1, diff);
		update(vals[idx].left, diff);

		if (recurse(idx + 1)) {
			return true;
		}

		pass[vals[idx].left - 1] = pass[vals[idx].left] = 0;
		update(vals[idx].left - 1, 0);
		update(vals[idx].left, 0);
	}
	if (vals[idx].right + 1 < N
			&& pass[vals[idx].right + 1] == 0 && pass[vals[idx].right] == 0
			&& istart[vals[idx].right + 1] == 0 && iend[vals[idx].right + 1] == 1) {

		pass[vals[idx].right + 1] = pass[vals[idx].right] = diff;
		update(vals[idx].right + 1, diff);
		update(vals[idx].right, diff);

		if (recurse(idx + 1)) {
			return true;
		}

		pass[vals[idx].right + 1] = pass[vals[idx].right] = 0;
		update(vals[idx].right + 1, 0);
		update(vals[idx].right, 0);
	}

	return false;
}

int not_main() {
	ifstream fin("example_input.txt");
	fill(pass, pass + N, 0);
	fill(segtree, segtree + N + N, 0);

	vals = vector<Interval>(M);
	for (int i = 0; i < M; i++) {
		fin >> vals[i].left >> vals[i].right >> vals[i].val;
//		cin >> intervals[i].left >> intervals[i].right >> intervals[i].val;
		vals[i].left--;
		vals[i].right--;
		istart[vals[i].left]++;
		iend[vals[i].right + 1]++;
	}
	sort(vals.begin(), vals.end(), comp_left);
	for (int i=0; i<M; i++) {
		for (int j=0; j<M; j++) {
			if (i == j) continue;
			if (vals[i].left == vals[j].left) {
				if (vals[i].right < vals[j].right) {
					vals[j].left = vals[i].right + 1;
					vals[j].val ^= vals[i].val;
				}
				else if (vals[i].right > vals[j].right) {
					vals[i].left = vals[j].right + 1;
					vals[i].val ^= vals[j].val;
				}
				else {
					assert(false);
				}
			}
			else if (vals[i].right == vals[j].right) {
				if (vals[i].left < vals[j].left) {
					vals[i].right = vals[j].left - 1;
					vals[i].val ^= vals[j].val;
				}
				else if (vals[i].left > vals[j].left) {
					vals[j].right = vals[i].left - 1;
					vals[j].val ^= vals[i].val;
				}
				else {
					assert(false);
				}
			}
			else if (vals[i].right < vals[j].left) break;
		}
	}
	sort(vals.begin(), vals.end(), comp_right);
	while (vals.back().left == MX) vals.pop_back();
	debug(vals.size());


	int cur_sum = 0;
	for (int i = 0; i < N; i++) {
		ch.insert(i);
		cur_sum += istart[i] - iend[i];
		freq[i] = cur_sum;
	}
	fill(istart, istart+N, 0);
	fill(iend, iend+N, 0);
	fill(used, used + N, vector<int>());

	sort(vals.begin(), vals.end(), comp_size);

	recurse(0);

	int n = 69200;
	int m = 69799;
	for (int i = n; i < m; i++) {
		cout << by[i] << ' ';
	}
	cout << endl;
	cout << istart[n] << ' ' << iend[n] << endl;
	n = m;
	cout << istart[n] << ' ' << iend[n] << endl;
	++n;
	cout << istart[n] << ' ' << iend[n] << endl;


//	for (int i=0; i<N; i++) {
//		cout << pass[i] << endl;
//	}
}
