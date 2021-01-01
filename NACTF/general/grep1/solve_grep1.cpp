#include <fstream>
#include <iostream>
#include <set>
#include <string>

using namespace std;

int main() {
    freopen("flag.txt", "r", stdin);
    cin.tie(0)->sync_with_stdio(0);

    string s;
    while (cin >> s) {
        if (s.size() != 52) continue;
        s = s.substr(6);
        s.pop_back();

        set<char> seen;
        for (int i=0; i<10; ++i) {
            seen.insert(s[i]);
        }
        bool ok = true;
        for (auto it=seen.begin(); it!=seen.end(); ++it) {
            if (*it != 'n' && *it != 'a' && *it != 'c') {
                ok = false;
                break;
            }
        }
        if (!ok) continue;

        seen.clear();
        for (int i=0; i<14; ++i) {
            seen.insert(s[s.size() - i - 1]);
        }
        for (auto it=seen.begin(); it!=seen.end(); ++it) {
            if (*it != 'c' && *it != 't' && *it != 'f') {
                ok = false;
                break;
            }
        }
        if (!ok) continue;
        
        if (ok) {
            cout << "nactf{" << s << '}' << endl;
        }
    }
}
