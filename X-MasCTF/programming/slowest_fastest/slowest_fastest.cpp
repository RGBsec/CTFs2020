#include <iostream>
#include <fstream>
#include <cassert>
#include <chrono>

using namespace std;

typedef long long ll;

const int MN = 1001001;

ll N, K, P, Q;
ll V[MN];

// P is always higher than Q, and K is number of workers with speed P
bool check(const ll days) {
    ll hi_ct = 0;
    for (int i=0; i<N; ++i) {
        if (P * days < V[i]) return false;
        hi_ct += max(0LL, (V[i] - (Q * days) + P - Q - 1) / (P - Q));
    }
    return hi_ct <= K * days;
}

int main() {
    //auto start = chrono::high_resolution_clock::now();
    cin.tie(0)->sync_with_stdio(0);
    cin >> N >> K >> P >> Q;
    assert(P != Q);

    if (P < Q) {
        swap(P, Q);
        K = N - K;
    }

    ll a, c, mod;
    cin >> V[0] >> a >> c >> mod;
    for (int i=1; i<N; ++i) {
        V[i] = (a * V[i-1] + c) % mod;
    }

    ll lo = 0, hi = (mod * N + Q - 1) / Q;
    while (lo < hi) {
        const ll mid = (lo + hi) / 2;
        if (check(mid)) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }

    //auto finish = chrono::high_resolution_clock::now();
    //cerr << chrono::duration_cast<chrono::duration<double>>(finish - start).count() << endl;
    cout << lo << '\n';
}
