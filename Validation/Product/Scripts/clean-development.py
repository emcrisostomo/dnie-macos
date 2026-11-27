#!/usr/bin/python3
"""Safely dispose of the selected macOS development build slot."""

from contextlib import ExitStack, contextmanager
import errno
import fcntl
import os
from pathlib import Path
import re
import runpy
import secrets
import signal
import stat
import subprocess
import sys

REPOSITORY = Path(__file__).resolve().parents[3]
SLOTS = {"T067", "T083CleanIncremental", "T083Upgrade"}
IDENTIFIER = "org.dniemacos.dnietoken.tokenextension"
SOURCE_HOST = ("Build", "Products", "Release", "DNIeTokenHost.app")
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
FILE_FLAGS = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
BLOCKING_FLAGS = (
    stat.UF_IMMUTABLE | stat.UF_APPEND | stat.UF_NOUNLINK
    | stat.SF_IMMUTABLE | stat.SF_APPEND | stat.SF_NOUNLINK
)


class CleanError(Exception):
    pass


def entry_info(parent, name):
    return os.stat(name, dir_fd=parent, follow_symlinks=False)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_flags)


def fingerprint(info):
    return (identity(info), info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def require_identity(expected, observed):
    if identity(expected) != identity(observed):
        raise CleanError("A checked directory or build entry changed.")


def require_unchanged(expected, observed):
    if fingerprint(expected) != fingerprint(observed):
        raise CleanError("A checked build entry changed.")


def validate_slot_entry(info, device, *, directory):
    mode = info.st_mode
    if (info.st_uid != os.geteuid() or info.st_dev != device
            or mode & 0o7022 or info.st_flags & BLOCKING_FLAGS):
        raise CleanError("The build tree has an unsafe owner, mode, flag, or filesystem.")
    if directory:
        if not stat.S_ISDIR(mode) or mode & 0o700 != 0o700:
            raise CleanError("A build directory is not a modifiable, unlinked directory.")
    elif not stat.S_ISREG(mode) or info.st_nlink != 1:
        raise CleanError("The build tree contains a link or unsupported file type.")


class BuildSlot:
    directory_flags = DIR_FLAGS
    entry_info = staticmethod(entry_info)
    require_identity = staticmethod(require_identity)
    require_unchanged = staticmethod(require_unchanged)

    def __init__(self, root, slot, ancestor_acl, entry_acl):
        self.repository = root
        self.path = root / "DerivedData" / slot
        self.anchors = []
        self.ancestor_acl = ancestor_acl
        self.acl = entry_acl

    def open_root(self, stack, *, lock_fd=None):
        path = self.repository
        if not path.is_absolute() or ".." in path.parts or path == Path("/"):
            raise CleanError("The repository path must be a canonical absolute path.")
        parent = os.open("/", DIR_FLAGS)
        stack.callback(os.close, parent)
        self.device = os.fstat(parent).st_dev
        self.ancestor_acl(parent)
        for name in path.parts[1:]:
            fd = os.open(name, DIR_FLAGS, dir_fd=parent)
            stack.callback(os.close, fd)
            info = os.fstat(fd)
            require_identity(info, entry_info(parent, name))
            trusted_sticky = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            if (info.st_uid not in (0, os.geteuid()) or info.st_dev != self.device
                    or (info.st_mode & 0o022 and not trusted_sticky)):
                raise CleanError("A repository ancestor has unsafe ownership, permissions, or filesystem.")
            self.ancestor_acl(fd)
            self.anchors.append((parent, name, fd, info))
            parent = fd

        repository_info = os.fstat(parent)
        if repository_info.st_uid != os.geteuid() or repository_info.st_mode & 0o022:
            raise CleanError("The repository directory must belong to the invoking user.")
        if lock_fd is not None:
            require_identity(repository_info, os.fstat(lock_fd))
        try:
            fcntl.flock(parent if lock_fd is None else lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise CleanError("A development build, install, recovery, or clean is already running.") from None
        self.revalidate_anchors()
        return parent

    def open_directories(self, stack, parent, names, *, create=False,
                         private_first=False, private_last=False):
        for index, name in enumerate(names):
            try:
                info = entry_info(parent, name)
            except FileNotFoundError:
                if not create:
                    return None
                self.revalidate_anchors()
                os.mkdir(name, 0o700, dir_fd=parent)
                info = entry_info(parent, name)
            validate_slot_entry(info, self.device, directory=True)
            is_private = (private_first and index == 0) or (private_last and index == len(names) - 1)
            if is_private and stat.S_IMODE(info.st_mode) != 0o700:
                raise CleanError("A development recovery directory is not private (mode 0700).")
            fd = os.open(name, DIR_FLAGS, dir_fd=parent)
            stack.callback(os.close, fd)
            require_unchanged(info, os.fstat(fd))
            self.acl(fd)
            self.anchors.append((parent, name, fd, info))
            parent = fd
        self.revalidate_anchors()
        return parent

    def revalidate_anchors(self):
        for parent, name, fd, expected in self.anchors:
            require_identity(expected, entry_info(parent, name))
            require_identity(expected, os.fstat(fd))

    @contextmanager
    def open_entry(self, parent, name, expected):
        directory = stat.S_ISDIR(expected.st_mode)
        validate_slot_entry(expected, self.device, directory=directory)
        require_unchanged(expected, entry_info(parent, name))
        fd = os.open(name, DIR_FLAGS if directory else FILE_FLAGS, dir_fd=parent)
        try:
            require_unchanged(expected, os.fstat(fd))
            self.acl(fd)
            yield fd
        finally:
            os.close(fd)

    def snapshot(self, fd):
        entries = {}
        for name in os.listdir(fd):
            info = entry_info(fd, name)
            with self.open_entry(fd, name, info) as child:
                descendants = self.snapshot(child) if stat.S_ISDIR(info.st_mode) else None
                require_unchanged(info, os.fstat(child))
            entries[name] = (info, descendants)
        return entries

    def retire_and_dispose(self, parent, name, fd, entries, label, publish):
        """Detach checked output before deletion so an interruption permits retry."""
        retired = f".retired-{label}-{secrets.token_hex(12)}"
        self.revalidate_anchors()
        try:
            publish(parent, name, parent, retired)
            os.fchmod(fd, 0o700)
            observed = os.fstat(fd)
            for index, (anchor_parent, anchor_name, anchor_fd, _) in enumerate(self.anchors):
                if anchor_parent == parent and anchor_name == name and anchor_fd == fd:
                    self.anchors[index] = (parent, retired, fd, observed)
                    break
            else:
                raise CleanError("The retired build entry has no checked anchor.")
            self.revalidate_anchors()
            self.dispose_contents(fd, entries, self.revalidate_anchors)
            self.revalidate_anchors()
            os.rmdir(retired, dir_fd=parent)
            os.fsync(parent)
        except BaseException:
            # The name contains no identity/hash or credential information.
            try:
                entry_info(parent, retired)
            except FileNotFoundError:
                pass
            else:
                print(f"development_retired_output={retired}", file=sys.stderr)
                print("Interrupted disposal retained private output for explicit review.", file=sys.stderr)
            raise

    def dispose_contents(self, fd, entries, check_parent):
        check_parent()
        if set(os.listdir(fd)) != entries.keys():
            raise CleanError("The contents of a checked build directory changed.")
        for name, (expected, nested) in entries.items():
            check_parent()
            with self.open_entry(fd, name, expected) as child:
                if nested is None:
                    require_unchanged(expected, entry_info(fd, name))
                    os.unlink(name, dir_fd=fd)
                else:
                    def check_child():
                        check_parent()
                        require_identity(expected, entry_info(fd, name))
                        require_identity(expected, os.fstat(child))

                    self.dispose_contents(child, nested, check_child)
                    check_child()
                    os.rmdir(name, dir_fd=fd)


def observe_lsof(path):
    result = subprocess.run(
        ["/usr/sbin/lsof", "-nP", "-t", "+w", "-p", f"^{os.getpid()}", "+D", str(path)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False,
    )
    rows = result.stdout.splitlines()
    if result.stderr or result.returncode not in (0, 1):
        raise CleanError("Unable to establish whether the build slot is in use.")
    if rows:
        if all(re.fullmatch(rb"[0-9]+", row) for row in rows):
            raise CleanError("A process is using the development build slot.")
        raise CleanError("Unable to interpret the build-slot usage inspection.")
    if result.returncode != 1:
        raise CleanError("Unable to establish whether the build slot is in use.")


def registration_file_is_in_slot(path, slot):
    if not path.is_absolute() or ".." in path.parts:
        raise CleanError("The source registration has an ambiguous path.")
    resolved = path.resolve()
    slot_info = slot.stat()
    for location in (resolved, *resolved.parents):
        try:
            if os.path.samestat(slot_info, location.stat()):
                return True
        except FileNotFoundError:
            continue
    # Includes stale registrations under the slot.
    return slot in resolved.parents or resolved == slot


def observe_registration(path, pluginkit):
    result = subprocess.run(
        [str(pluginkit), "-m", "-A", "-D", "-vvv", "-i", IDENTIFIER],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
        check=False, text=True,
    )
    if result.returncode or result.stderr:
        raise CleanError("Unable to inspect PlugInKit source registrations.")
    if not result.stdout.strip():
        return
    header = re.compile(r"^\s*[+!\-=?]?\s*" + re.escape(IDENTIFIER) + r"\s*\([^)]*\)\s*$")
    paths = []
    seen_header = 0
    for line in result.stdout.splitlines():
        if header.fullmatch(line):
            if seen_header and len(paths) != seen_header:
                raise CleanError("The PlugInKit source registration has no unique path.")
            seen_header += 1
        elif line.lstrip().startswith("Path = "):
            if len(paths) + 1 != seen_header:
                raise CleanError("The PlugInKit source registration has no unique path.")
            paths.append(Path(line.lstrip().removeprefix("Path = ")))
    if not paths or len(paths) != seen_header:
        raise CleanError("Unable to interpret the PlugInKit source registration.")
    if any(registration_file_is_in_slot(registered, path) for registered in paths):
        raise CleanError("A PlugInKit registration still refers to the development build slot.")


def require_no_acl(api, fd):
    # Darwin acl_get_fd_np(3) uses ENOENT for a descriptor without an ACL.
    import ctypes
    ctypes.set_errno(0)
    acl = api.acl_get_fd_np(fd, 0x100)
    if acl:
        api.acl_free(acl)
        raise CleanError("A build or recovery entry has an extended ACL.")
    if ctypes.get_errno() != errno.ENOENT:
        raise CleanError("A build or recovery entry ACL could not be inspected.")


def clean(context, stack, root_fd, pluginkit, recovery):
    fd = context.open_directories(stack, root_fd, ("DerivedData", context.path.name))
    if fd is None:
        return "absent"

    slot_parent, name, _, info = context.anchors[-1]
    entries = context.snapshot(fd)
    require_unchanged(info, os.fstat(fd))
    observe_registration(context.path, pluginkit)
    observe_lsof(context.path)
    context.revalidate_anchors()
    require_unchanged(info, os.fstat(fd))

    context.retire_and_dispose(slot_parent, name, fd, entries,
                               context.path.name, recovery["publish"])
    try:
        entry_info(slot_parent, name)
    except FileNotFoundError:
        return "removed"
    raise CleanError("The build slot was recreated during cleanup.")


def interrupted(_signum, _frame):
    raise KeyboardInterrupt


def main():
    if os.geteuid() == 0:
        raise CleanError("Do not run development cleanup through sudo/root.")
    signal.signal(signal.SIGHUP, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    os.umask(0o077)
    arguments = sys.argv[1:]
    root = REPOSITORY
    pluginkit = Path("/usr/bin/pluginkit")
    inspector = REPOSITORY / "Validation/Product/Scripts/inspect-pilot-artifact.sh"
    if len(arguments) >= 3 and arguments[0] == "--fixture":
        root, bin_dir = (Path(value) for value in arguments[1:3])
        if (root.parts[:3] != ("/", "private", "tmp") or root.parent != bin_dir.parent
                or not root.parent.name.startswith((
                    "dnie-clean-development-test.", "dnie-developer-workflow-test.",
                    "dnie-pilot-lifecycle-test.",
                ))):
            raise CleanError("The clean fixture must be in an isolated temporary directory.")
        pluginkit = bin_dir / "pluginkit"
        inspector = bin_dir / "artifact-inspector"
        arguments = arguments[3:]

    operation = arguments[0] if arguments else "clean"
    valid = {"clean": 0, "--lock": 2, "--check-inactive": 2, "--restore": 3, "--prune": 3}
    if operation not in valid or len(arguments) != valid[operation]:
        raise CleanError("Invalid development cleanup arguments.")
    if arguments and not arguments[1].isdigit():
        raise CleanError("The development lock descriptor is invalid.")
    fd = int(arguments[1]) if arguments else None
    if fd is not None and fd < 3:
        raise CleanError("The development lock descriptor is invalid.")

    slot = os.environ.get("DNIE_DEVELOPMENT_BUILD_SLOT", "T067")
    if operation in {"--lock", "--restore", "--prune"}:
        slot = "T067"
    if slot not in SLOTS:
        raise CleanError("DNIE_DEVELOPMENT_BUILD_SLOT must be T067 or T083CleanIncremental, or T083Upgrade.")

    release = runpy.run_path(str(REPOSITORY / "Release/release.py"))
    recovery = runpy.run_path(str(Path(__file__).with_name("development-recovery.py")))
    try:
        acl_api = release["darwin_acl_api"]()
        context = BuildSlot(root, slot, release["require_safe_acl"], lambda fd: require_no_acl(acl_api, fd))
        with ExitStack() as stack:
            repository_fd = context.open_root(stack, lock_fd=fd)
            if operation == "clean":
                result = clean(context, stack, repository_fd, pluginkit, recovery)
                print(f"development_clean={result}")
                print(f"development_build_slot={slot}")
            elif operation == "--check-inactive":
                build_fd = context.open_directories(stack, repository_fd, ("DerivedData", slot))
                if build_fd is not None:
                    observe_lsof(context.path)
                    context.revalidate_anchors()
            elif operation == "--restore":
                if recovery["restore"](context, stack, repository_fd, inspector, arguments[2], SOURCE_HOST):
                    print("development_recovery_source=restored")
            elif operation == "--prune":
                def require_inactive(path):
                    observe_registration(path, pluginkit)
                    observe_lsof(path)

                if recovery["prune"](context, stack, repository_fd, inspector,
                                     arguments[2], SOURCE_HOST, require_inactive):
                    print("development_recovery_source=disposed")
    except release["ReleaseError"]:
        raise CleanError("A path ACL is unsafe or could not be inspected.") from None
    except recovery["RecoveryError"] as error:
        raise CleanError(str(error)) from None


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, RecursionError):
        sys.exit("Development cleanup stopped before completing the selected slot.")
    except CleanError as error:
        sys.exit(str(error))
    except subprocess.TimeoutExpired:
        sys.exit("Development cleanup stopped because a read-only check timed out.")
    except OSError as error:
        sys.exit(f"Development cleanup stopped on a filesystem or inspection error (errno {error.errno}).")
