#include <bits/stdc++.h>

using namespace std;

typedef __int128 ll;

ll abs(ll x) {
    return x < 0 ? -x : x;
}

const ll A = 69925405969, B = 48507179354, C = 32417688895;
//const ll A = 299, B = 355, C = 251;

ll egcd(ll a, ll b, ll& x, ll& y) {
    if (a % b == 0) {
        x = 0;
        y = 1;
        return b;
    }
    ll nx, ny;
    ll ret = egcd(b, a % b, nx, ny);
    x = ny;
    y = nx - ny * (a / b);
    return ret;
}

ll total(ll x, ll y, ll k, const ll g) {
    x += k * B / g;
    y -= k * A / g;
    return abs(x) + abs(y);
}

string to_string(ll x) {
    string s;
    bool neg = x < 0;
    if (neg) x = -x;
    while (x) {
        s += (x % 10) + '0';
        x /= 10;
    }
    if (s.empty()) s = '0';
    if (neg) s += '-';
    reverse(s.begin(), s.end());
    return s;
}

bool check(const ll c, ll& x, ll& y, ll& g) {
    g = egcd(abs(A), abs(B), x, y);
    if (c % g > 0) return false;
    x *= c / g;
    y *= c / g;
    if (A < 0) x = -x;
    if (B < 0) y = -y;

    ll lo = -1e18, hi = 1e18;
    while (lo < hi) {
        ll mid = (lo + hi) >> 1;
        if (total(x, y, mid, g) > total(x, y, mid+1, g)) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    x += lo * B / g;
    y -= lo * A / g;

    return true;
}

const ll MX = 100000;

ll best[3] = {B*C, A*C, -2*A*B};
void ch_best(ll x, ll y, ll z) {
    ll bsum = abs(best[0]) + abs(best[1]) + abs(best[2]);
    ll csum = abs(x) + abs(y) + abs(z);
    if (bsum > csum && csum != 0) {
        best[0] = x;
        best[1] = y;
        best[2] = z;
    }
}

int main() {
    for (ll z=-MX; z<=MX; ++z) {
        ll x, y, g;
        if (check(-C*z, x, y, g)) {
            ch_best(x, y, z);
            cout << to_string(x) << ' ' << to_string(y) << ' ' << to_string(z) << '\n';
            assert(A*x + B*y + C*z == 0);
        }
    }
    cout << to_string(best[0]) << ' ' << to_string(best[1]) << ' ' << to_string(best[2]) << endl;
}

