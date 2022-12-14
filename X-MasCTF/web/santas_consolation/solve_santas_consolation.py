from base64 import b64decode
from urllib.parse import unquote

k = "MkVUTThoak44TlROOGR6TThaak44TlROOGR6TThWRE14d0hPMnczTTF3M056d25OMnczTTF3M056d1hPNXdITzJ3M00xdzNOenduTjJ3M00xdzNOendYTndFRGY0WURmelVEZjNNRGYyWURmelVEZjNNRGYwRVRNOGhqTjhOVE44ZHpNOFpqTjhOVE44ZHpNOEZETXh3SE8ydzNNMXczTnp3bk4ydzNNMXczTnp3bk13RURmNFlEZnpVRGYzTURmMllEZnpVRGYzTURmeUlUTThoak44TlROOGR6TThaak44TlROOGR6TThCVE14d0hPMnczTTF3M056d25OMnczTTF3M056dzNOeEVEZjRZRGZ6VURmM01EZjJZRGZ6VURmM01EZjFBVE04aGpOOE5UTjhkek04WmpOOE5UTjhkek04bFRPOGhqTjhOVE44ZHpNOFpqTjhOVE44ZHpNOGRUTzhoak44TlROOGR6TThaak44TlROOGR6TThSVE14d0hPMnczTTF3M056d25OMnczTTF3M056d1hPNXdITzJ3M00xdzNOenduTjJ3M00xdzNOenduTXlFRGY0WURmelVEZjNNRGYyWURmelVEZjNNRGYzRVRNOGhqTjhOVE44ZHpNOFpqTjhOVE44ZHpNOGhETjhoak44TlROOGR6TThaak44TlROOGR6TThGak14d0hPMnczTTF3M056d25OMnczTTF3M056d25NeUVEZjRZRGZ6VURmM01EZjJZRGZ6VURmM01EZjFFVE04aGpOOE5UTjhkek04WmpOOE5UTjhkek04RkRNeHdITzJ3M00xdzNOenduTjJ3M00xdzNOendITndFRGY0WURmelVEZjNNRGYyWURmelVEZjNNRGYxRVRNOGhqTjhOVE44ZHpNOFpqTjhOVE44ZHpNOFZETXh3SE8ydzNNMXczTnp3bk4ydzNNMXczTnp3WE94RURmNFlEZnpVRGYzTURmMllEZnpVRGYzTURmeUlUTThoak44TlROOGR6TThaak44TlROOGR6TThkVE84aGpOOE5UTjhkek04WmpOOE5UTjhkek04WlRNeHdITzJ3M00xdzNOenduTjJ3M00xdzNOendITXhFRGY0WURmelVEZjNNRGYyWURmelVEZjNNRGYza0RmNFlEZnpVRGYzTURmMllEZnpVRGYzTURmMUVUTTAwMDBERVRDQURFUg==";
k1 = b64decode(k)[::-1]


def unbobify(s):
    s3 = b64decode(s)
    assert s3.startswith(b"D@\xc0\t1\x03\xd3M4")
    s2 = s3[9:]
    s2 = unquote(b''.join([chr(int(x)).encode() for x in s2.split(b'|')]).decode())
    s1 = s2.replace('[]', '').replace('z', '_').replace('t', '7').replace('i', '1').replace('e', '3').replace('a', '4')
    return s1


print(unbobify(k1))

# X-MAS{s4n74_w1sh3s_y0u_cr4c1un_f3r1c17}