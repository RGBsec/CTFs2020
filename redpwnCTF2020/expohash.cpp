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
	ll val;

	void print() {
		cout << left << ' ' << right << ' ' << val << ' ' << endl;
	}
};
bool comp_left(const Interval &a, const Interval &b) {
	if (a.left == b.left) return a.right > b.right;
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

int query(int tree[], int left, int right) {
	left += N;
	right += N + 1;

	int ret = 0;
	while (left < right) {
		if (left & 1) {
			ret ^= tree[left++];
		}
		if (right & 1) {
			ret ^= tree[--right];
		}
		left >>= 1;
		right >>= 1;
	}

	return ret;
}
int segtree[N * 2];

int pass[N];
int iend[N];

bool DEBUG = false;

int main() {
	ios_base::sync_with_stdio(false);
	cin.tie(nullptr);
	cout.tie(nullptr);

	if (DEBUG) {
		freopen(string("example_input.txt").c_str(), "r", stdin); // for debug
	}

	fill(pass, pass + N, 0);
	fill(segtree, segtree + N + N, 0);

	vector<Interval> vals(M);
	for (int i = 0; i < M; i++) {
		cin >> vals[i].left >> vals[i].right >> vals[i].val;
		vals[i].left--;
		vals[i].right--;
		assert(vals[i].val <= (1LL << 31));
	}
	bool change = false;
	int ct = 0;
	do {
		change = false;
		if (DEBUG && (++ct & 255) == 0) {
			cout << ct << ' ' << vals.size() << '\n';
		}

		// we only care about endpoints
		sort(vals.begin(), vals.end(), comp_right);
		while (vals.back().right == MX) vals.pop_back();
		for (int i=0; i+1<vals.size(); i++) {
			if (vals[i].right == vals[i+1].right) {
				if (vals[i].left < vals[i+1].left) {
					vals[i].right = vals[i+1].left - 1;
					vals[i].val ^= vals[i+1].val;
				}
				else if (vals[i+1].left > vals[i].left) {
					vals[i+1].right = vals[i].left - 1;
					vals[i+1].val ^= vals[i].val;
				}
				else {
					vals[i].left = MX;
					vals[i].right = MX;
					assert(vals[i].val == vals[i+1].val);
				}
				change = true;
			}
		}
	}
	while (change);

	fill(iend, iend+N, -1);
	for (int i=0; i<vals.size(); i++) {
		assert(iend[vals[i].right] == -1);
		iend[vals[i].right] = i;
	}

	for (int i=0; i<N; i++) {
		if (iend[i] == -1) {
			pass[i] = 0;
		}
		else {
			pass[i] = vals[iend[i]].val ^ query(segtree, vals[iend[i]].left, vals[iend[i]].right);
		}
		update(segtree, i, pass[i]);
	}


	for (int i=0; i<N; i++) {
		cout << pass[i] << '\n';
	}
}
