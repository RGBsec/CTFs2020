#include <bits/stdc++.h>

using namespace std;

const int MN = 200;
const int ML = 100001;
const int MOD = 666013;

int N, L, F;
bool mat[MN][MN];
int dp[ML][MN];

int main() {
    cin >> N >> L >> F;
    for (int i=0; i<N; ++i) {
        for (int j=0; j<N; ++j) {
            cin >> mat[i][j];
        }
    }
    for (int i=0; i<F; ++i) {
        int x;
        cin >> x;
        --x;
        for (int j=0; j<N; ++j) {
            mat[x][j] = mat[j][x] = false;
        }
    }

    dp[0][0] = 1;
    for (int i=1; i<=L; ++i) {
        for (int j=0; j<N; ++j) {
            for (int k=0; k<N; ++k) {
                dp[i][j] += mat[k][j] ? dp[i-1][k] : 0;
                if (dp[i][j] >= MOD) dp[i][j] -= MOD;
            }
        }
    }

    cout << dp[L][N-1] << endl;
}
