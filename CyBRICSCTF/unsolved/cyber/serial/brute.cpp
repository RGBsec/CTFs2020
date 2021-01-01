#include <iostream>

using namespace std;

typedef long long ll;

int main() {
	const ll N = 1000000;
	for (ll c=1; c<N; c++) {
		if ((c & 2047) == 0)
			cout << c << '\n';
		ll cc = c*c*c;
		for (ll a=1; a<c; a++) {
			ll ca = a*a*a;
			ll lo = 1, hi = N;
			while (lo < hi) {
				ll b = (lo + hi) / 2;
				if (ca + (b*b*b) < cc) {
					lo = b + 1;
				}
				else {
					hi = b;
				}
			}

			if (ca + (lo*lo*lo) == cc) {
				cout << ca << ' ' << (lo*lo*lo) << ' ' << cc << endl;
			}
		}
	}

	return 0;
}
