console.log("%c██████╗░██╗░░░░░██╗░░░██╗██╗░░░██╗██╗░░██╗\n\██╔══██╗██║░░░░░██║░░░██║██║░░░██║██║░██╔╝\n██████╦╝██║░░░░░██║░░░██║██║░░░██║█████═╝░\n██╔══██╗██║░░░░░██║░░░██║██║░░░██║██╔═██╗░\n██████╦╝███████╗╚██████╔╝╚██████╔╝██║░╚██╗\n╚═════╝░╚══════╝░╚═════╝░░╚═════╝░╚═╝░░╚═╝\n","color: #5cdb95");console.log("🐢 Javascript Challenge 🐢");console.log("Call win(<string>) with the correct parameter to get the flag");console.log("And don't forget to subscribe to our newsletter :D");
function check(s) {
    const k="MkVUTThoak44TlROOGR6TThaak44TlROOGR6TThWRE14d0hPMnczTTF3M056d25OMnczTTF3M056d1hPNXdITzJ3M00xdzNOenduTjJ3M00xdzNOendYTndFRGY0WURmelVEZjNNRGYyWURmelVEZjNNRGYwRVRNOGhqTjhOVE44ZHpNOFpqTjhOVE44ZHpNOEZETXh3SE8ydzNNMXczTnp3bk4ydzNNMXczTnp3bk13RURmNFlEZnpVRGYzTURmMllEZnpVRGYzTURmeUlUTThoak44TlROOGR6TThaak44TlROOGR6TThCVE14d0hPMnczTTF3M056d25OMnczTTF3M056dzNOeEVEZjRZRGZ6VURmM01EZjJZRGZ6VURmM01EZjFBVE04aGpOOE5UTjhkek04WmpOOE5UTjhkek04bFRPOGhqTjhOVE44ZHpNOFpqTjhOVE44ZHpNOGRUTzhoak44TlROOGR6TThaak44TlROOGR6TThSVE14d0hPMnczTTF3M056d25OMnczTTF3M056d1hPNXdITzJ3M00xdzNOenduTjJ3M00xdzNOenduTXlFRGY0WURmelVEZjNNRGYyWURmelVEZjNNRGYzRVRNOGhqTjhOVE44ZHpNOFpqTjhOVE44ZHpNOGhETjhoak44TlROOGR6TThaak44TlROOGR6TThGak14d0hPMnczTTF3M056d25OMnczTTF3M056d25NeUVEZjRZRGZ6VURmM01EZjJZRGZ6VURmM01EZjFFVE04aGpOOE5UTjhkek04WmpOOE5UTjhkek04RkRNeHdITzJ3M00xdzNOenduTjJ3M00xdzNOendITndFRGY0WURmelVEZjNNRGYyWURmelVEZjNNRGYxRVRNOGhqTjhOVE44ZHpNOFpqTjhOVE44ZHpNOFZETXh3SE8ydzNNMXczTnp3bk4ydzNNMXczTnp3WE94RURmNFlEZnpVRGYzTURmMllEZnpVRGYzTURmeUlUTThoak44TlROOGR6TThaak44TlROOGR6TThkVE84aGpOOE5UTjhkek04WmpOOE5UTjhkek04WlRNeHdITzJ3M00xdzNOenduTjJ3M00xdzNOendITXhFRGY0WURmelVEZjNNRGYyWURmelVEZjNNRGYza0RmNFlEZnpVRGYzTURmMllEZnpVRGYzTURmMUVUTTAwMDBERVRDQURFUg==";
    const k1=atob(k).split('').reverse().join('');
    return bobify(s)===k1;
}
function bobify(s) {
    if (~s.indexOf('a') || ~s.indexOf('t') || ~s.indexOf('e') || ~s.indexOf('i') || ~s.indexOf('z')) return "[REDACTED]";
    const s1 = s.replace(/4/g, 'a').replace(/3/g, 'e').replace(/1/g, 'i').replace(/7/g, 't').replace(/_/g, 'z').split('').join('[]');
    const s2 = encodeURI(s1).split('').map(c => c.charCodeAt(0)).join('|');
    const s3 = btoa("D@\xc0\t1\x03\xd3M4" + s2);return s3;
}
function win(x) {
    return check(x) ? "X-MAS{"+x+"}" : "[REDACTED]";
}