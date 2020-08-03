# **InCTF 2020: Lookout Foxy**
by Klanec

Challenge Author: *g4rud4*<br>
Category: _Forensics_

### **The Challenge**
We are given an Expert Witness format image dump of a windows XP hard disk and the clue that our suspect uses a "genuine" old chat client to communicate.

### **Mounting the image**
First things first. We must mount the image. There are many methods to do this, some more manual than others. I used [*imagemounter*][imgmounter] which made the process seamless and convenient. You can install it with

`pip3 install imagemounter`

Once installed, we can simply do the following (though you might need to use sudo):
```
$ imount ./Lookout\ Foxy\ final.E01 
[+] Mounting image ./Lookout Foxy final.E01 using auto...
[+] Mounted raw image [1/1]
[+] Mounted volume 7.49 GiB 2:NTFS [Windows XP] on /tmp/im_2_5u5j8o4b_.
>>> Press [enter] to unmount the volume, or ^C to keep mounted... 

```
And just leave it running in another terminal. As you can see, it has mounted the image to `/tmp/im_2_5u5j8o4b_/` for us.


### **Flag Part 1**

Once I had the drive mounted, I spent a while analyzing the directory structure to understand:

- what programs are installed
- what users there are
- what files or programs could be of interest (system or otherwise)

I used the `tree` command to get the entire directory structure as follows:

`$ tree -a /tmp/im_2_5u5j8o4b_/ > tree.txt`

I find this easier than manually going through with a terminal or a file manager. Open it in a text editor and scroll through to investigate.

It appears that there is a Microsoft Outlook account and identity configured. 

```
│   │   ├── Local Settings
│   │   │   ├── Application Data
│   │   │   │   ├── GDIPFONTCACHEV1.DAT
│   │   │   │   ├── IconCache.db
│   │   │   │   ├── Identities
│   │   │   │   │   └── {72F33BC6-0035-4FE0-AED1-5870C5CA389E}
│   │   │   │   │       └── Microsoft
│   │   │   │   │           └── Outlook Express
│   │   │   │   │               ├── Deleted Items.dbx
│   │   │   │   │               ├── Drafts.dbx
│   │   │   │   │               ├── Folders.dbx
│   │   │   │   │               ├── Inbox.dbx
│   │   │   │   │               ├── Offline.dbx
│   │   │   │   │               ├── Outbox.dbx
│   │   │   │   │               ├── Pop3uidl.dbx
│   │   │   │   │               └── Sent Items.dbx
```
Those DBX files should contain emails if this Outlook account was actively being used from this PC. We can dump the emails with a super niche command line tool, `undbx`. Install like so:

`sudo apt install undbx`

And use as below:
```
$ undbx Inbox.dbx ~/Documents/CTF/inctf/forensics/foxy/undbx/ -v3
UnDBX v0.21 (Aug 29 2018)
Extracting 1 messages from Inbox.dbx to /home/klanec/Documents/CTF/inctf/forensics/foxy/undbx//Inbox: 100.0%
1 messages saved, 0 skipped, 0 errors, 0 files moved
Extracted 1 out of 1 DBX files
```
The other DBX files contained nothing, but it seems there is a lone email in the `Inbox.dbx` file that we have now managed to extract. Open the extracted email in a text-editor and you will see that the email has an encrypted attachment.

```
.
. (output truncated)
.
From: David Banjamin <davin.banjamin@gmail.com>
Date: Mon, 27 Jul 2020 19:38:43 +0530
Message-ID: <CAATHjt-3yJWu9_omTgRPp79GXsxCUjgMqvHOrLy652GzZOg=9A@mail.gmail.com>
Subject: Secret File
To: danial.banjamin008@gmail.com
Content-Type: multipart/mixed; boundary="000000000000ef6e6205ab6cdcd2"

--000000000000ef6e6205ab6cdcd2
Content-Type: multipart/alternative; boundary="000000000000ef6e6005ab6cdcd0"

--000000000000ef6e6005ab6cdcd0
Content-Type: text/plain; charset="UTF-8"

Attaching a Secret File

--000000000000ef6e6005ab6cdcd0
Content-Type: text/html; charset="UTF-8"

<div dir="ltr">Attaching a Secret File</div>

--000000000000ef6e6005ab6cdcd0--
--000000000000ef6e6205ab6cdcd2
Content-Type: application/pgp-encrypted; name="secret.gpg"
Content-Disposition: attachment; filename="secret.gpg"
Content-Transfer-Encoding: base64
Content-ID: <f_kd4l6uw10>
X-Attachment-Id: f_kd4l6uw10

hQGMAyHuKvK4GOsrAQv+OiBvJwsMyMaptMBHmISeGQeYw
.
(output truncated)
.
```
First lets extract the encrypted file. To do this, one could write a quick bash script or even copy/paste. But why would we do such a thing when a super niche command line tool exists for this already?

Install the MIME pack program with `sudo apt install mpack` and unpack with the `munpack` command as below:


```
$ munpack David\ Banjamin_davin.banjamin@_danial.banjamin__danial.banjami_Secret\ File.7729CC00.6F6A2780.eml 
tempdesc.txt: File exists
secret.gpg (application/pgp-encrypted)

$ file secret.gpg
secret.gpg: PGP RSA encrypted session key - keyid: F22AEE21 2BEB18B8 RSA (Encrypt or Sign) 3072b .

```
Great. We can understand from the file header that it is a PGP encrypted file and from the extensions (*.gpg*) that it was most likely encrypted using the *GPG* software suite. Searching for `gpg` in our directory structure output reveals that it is installed AND that a key exists too.
```
├── Program Files
│   ├── GPG
│   │   └── secret.key
```
Lets import the key to gpg:
```
$ cd /tmp/im_2_5u5j8o4b_/Program Files/GPG
$ gpg --import secret.key 
gpg: keybox '/home/klanec/.gnupg/pubring.kbx' created
gpg: /home/klanec/.gnupg/trustdb.gpg: trustdb created
gpg: key 35E453B7B6FB578A: public key "Danial Banjamin <danial.benjamin008@gmail.com>" imported
gpg: key 35E453B7B6FB578A: secret key imported
gpg: Total number processed: 1
gpg:               imported: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1
```

And then try to decrypt the encrypted file: (below output truncated)

```
$ gpg -d secret.gpg 
gpg: encrypted with 3072-bit RSA key, ID 21EE2AF2B818EB2B, created 2020-03-21
      "Danial Banjamin <danial.benjamin008@gmail.com>"
Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Malesuada nunc vel risus commodo viverra. Suspendisse faucibus interdum posuere lorem ipsum. Sit amet facilisis magna etiam tempor orci eu lobortis elementum. Vestibulum sed arcu non odio euismod lacinia at quis. Rhoncus urna neque viverra justo nec. Mi in nulla posuere sollicitudin aliquam ultrices sagittis orci a. Mauris commodo quis imperdiet massa tincidunt nunc pulvinar sapien. Auctor elit sed vulputate mi. Sed elementum tempus egestas sed sed risus. Proin fermentum leo vel orci porta. Vel orci porta non pulvinar. A arcu cursus vitae congue mauris rhoncus aenean vel elit.

Giving away the top secret information. Don't tell that to anyone :)
...
Passing the information:
...
This is an important string. Don't share with anyone.
...
I will be sending you the important message in parts. Grab each and everything.
...
Here is the first part:
...
Important string: inctf{!_h0p3_y0u_L1k3d_s0lv1ng_7h3_F1rs7_p4r7_ 
...
```
And so, part 1 of the flag has been found!

`inctf{!_h0p3_y0u_L1k3d_s0lv1ng_7h3_F1rs7_p4r7_`

### **Flag Part 2**
Scanning through the directory tree reveals that Firefox is installed.
```
│   │   │   └── Mozilla
│   │   │       ├── Extensions
│   │   │       └── Firefox
│   │   │           ├── Crash Reports
│   │   │           │   ├── events
│   │   │           │   └── InstallTime20180621064021
│   │   │           ├── Profiles
│   │   │           │   └── 5ztdm4br.default
│   │   │           │       ├── addons.json
```
An active Firefox installation will have a profile that contains a wealth of forensic data. We can see one such profile existing in the above snippet (`Profiles -> 5ztdm4br.default`)
There is a great tool in development for firefox forensics called [*firefed*][firefed]. You can install it with pip, or pull from the git I have linked

`pip3 install firefed`

There is a lot of data to mine through from firefed, but the smoking gun is the `logins` module, which reveals that our suspect has saved a username and password to a fishy looking IP address:
```
$ cd /tmp/im_2_5u5j8o4b_/Documents and Settings/crimson/Application Data/Mozilla/Firefox/Profiles/5ztdm4br.default

$ firefed -p ./ logins
Host                   Username         Password                                  
---------------------  ---------------  ------------------------------------------
http://35.209.205.103  Danial_Banjamin  2!6BQ&e626g#YNWxsQWV9^knO8#85*E%6Zaxr@At42

```
Connecting to the remote server reveals a login page.
![connect][connect]

Inputting the saved credentials we found earlier reveals the second part of the flag: 
![flag_part2][flag_part2]

Flag part 2
`4nd_3njoy3d_7he_53c0nd_p4rt_0f_7h3_ch4ll3ng3}`


Connect parts 1 and 2 and we have the flag:
`inctf{!_h0p3_y0u_L1k3d_s0lv1ng_7h3_F1rs7_p4r7_4nd_3njoy3d_7he_53c0nd_p4rt_0f_7h3_ch4ll3ng3}`

Hats off to g4rud4 for writing such an interesting challenge.

Read more writeups by me here: https://klanec.github.io/

[imgmounter]: https://github.com/ralphje/imagemounter
[firefed]: https://github.com/numirias/firefed
[connect]: login.png
[flag_part2]: flag_part2.png
