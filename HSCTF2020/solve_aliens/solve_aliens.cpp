/*
 * solve_aliens.cpp
 *
 *  Created on: Jun 1, 2020
 *      Author: Stanley
 */

#include <iostream>
#include <fstream>

using namespace std;

typedef long long ll;

const int N = 500;
ll grid[N+1][N+1];
ll sums[N+1][N+1];
bool neg[N+1][N+1];

ll brute(int r1, int c1, int r2, int c2) {
	ll sum = 0;
	bool is_neg = false;
	for (int r=r1; r<=r2; ++r) {
		for (int c=c1; c<=c2; ++c) {
			sum += grid[r][c];
			if (grid[r][c] == -1) {
				is_neg = !is_neg;
			}
		}
	}


	if ((sum % 13) == 0) {
		if (is_neg) {
			sum = -sum;
		}
	}
	else {
		sum = 0;
	}

	cout << r1 << "," << c1 << " " << r2 << "," << c2 << " " << sum << " " << is_neg << endl;
	return sum;
}

int main() {
	ifstream fin("AlienMarking.txt");
	for (int i=1; i<=N; ++i) {
		for (int j=1; j<=N; ++j) {
			fin >> grid[i][j];
		}
	}

	for (int i=1; i<=N; ++i) {
		for (int j=1; j<=N; ++j) {
			sums[i][j] = grid[i][j] + sums[i-1][j] + sums[i][j-1] - sums[i-1][j-1];
			neg[i][j] = (grid[i][j] < 0) ^ neg[i-1][j] ^ neg[i][j-1] ^ neg[i-1][j-1];
//			cout << sums[i][j] << ' ';
		}
//		cout << endl;
	}

	ll ans = 0;
	for (int r1=1; r1<=N; ++r1) {
		cout << r1 << '\n';
		for (int c1=1; c1<=N; ++c1) {
			for (int r2=r1; r2<=N; ++r2) {
				for (int c2=c1; c2<=N; ++c2) {
//					ans += brute(r1,c1,r2,c2);
					ll cur = sums[r2][c2] - sums[r1-1][c2] - sums[r2][c1-1] + sums[r1-1][c1-1];
					bool is_neg = neg[r2][c2] ^ neg[r1 - 1][c2] ^ neg[r2][c1 - 1] ^ neg[r1-1][c1-1];

					if ((cur % 13) == 0) {
						if (is_neg) {
							cur = -cur;
						}
						ans += cur;
					}
					else {
						cur = 0;
					}
//					cout << r1 << "," << c1 << " " << r2 << "," << c2 << " " << cur << " " << is_neg << endl;
//					brute(r1, c1, r2, c2);
//					cout << endl;
				}
			}
		}
	}

	cout << ans << endl;
}
