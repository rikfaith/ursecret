# ursecret
Generate, store, and retrieve secrets via ssh

## Use Case

I use the following layering for large data stores:
1. RAID-5 or RAID-6 using mdadm
2. cryptsetup using LUKS
3. lvs/pvs
4. ext4fs

I'd like the data store to come online when the machine is booted without any
user intervention. This requires the machine can obtain the key at boot time
without a human present.

I want to protect the data store against theft. I.e., if the machine is
stolen and booted, the data store should not be decrypted. There are two
classes of machines that are configured like this:

- Machines on the local network. If these are stolen, they won't have access
  to the local network. In this case, storing LUKS keys on other machines on
  the local network suffices to protect against theft, assuming the key store
  machine isn't also stolen.
- Machine in co-location facilities. If these are stolen, they may have similar
  network access, but their theft should be noticed. In this case, storing
  LUKS keys on other machines on the Internet would require human intervention
  to disable the keys.

If partial keys are stored on multiple different machines, it will decrease
the probability that they required local-network keystores will be stolen; and
will increase the ease with which keys can be disabled for Internet-connected
machines.

Further, for any machines with a static IP, the key store can be IP-locked.

## Design Goals

1. Use ssh.
2. Use a single-file Python 3 script, for easy installability.
3. Manage ssh keys in a simple manner, allowing easy verification that things
are working as expected.
4. Manage LUKS keys in a simple manner, allowing reconstruction of the keys by
hand if necessary.

## Solution

Ssh already provides end-to-end encryption for the transport of LUKS key
fragments, including the ability to do IP locking.

The ursecret Python 3 script builds on ssh (using paramiko) to provide:
1. The ability to generate a passphrase-less key that is acceptable to the
target's ssh.
2. The ability to install this key on the target, with an appropriate entry in
~/.ssh/authorized keys.
3. The ability to then issue "put" and "get" commands against the target,
using the generated passphrase-less key to obtain LUKS key fragments.

The LUKS key fragments are stored in ~/.ursecret, and may be encrypted using
another symmetric key that is stored in plain text on the data store host
(TBD).

## Usage

    usage: ursecret.py [-h] [--remote REMOTE] [--local LOCAL] [--install] [--get KEY] [--put KEY VALUE] [--debug]

    Generate, store, and retrieve secrets via ssh

    optional arguments:
      -h, --help       show this help message and exit
      --remote REMOTE  name of remote host
      --local LOCAL    name of local host (for query purposes)
      --install        install new ssh key
      --get KEY        get named secret
      --put KEY VALUE  put named secret
      --debug          verbose debugging output
