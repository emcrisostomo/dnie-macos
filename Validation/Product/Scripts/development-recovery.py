"""Preserve and restore the exact signed source needed by pilot install recovery."""

from contextlib import contextmanager
import ctypes
import os
import re
import secrets
import shutil
import stat
import subprocess

APP = "DNIeTokenHost.app"
CACHE = ("Validation", "private", "DevelopmentRecovery")
HEX = re.compile(r"[0-9a-f]{40}")


class RecoveryError(Exception):
    pass


def inspect_app(path, inspector):
    """Return the verified production CDHash, or None for a non-recoverable build."""
    if inspector is None:
        display = subprocess.run(
            ["/usr/bin/codesign", "--display", "--verbose=4", str(path)],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30,
            check=False, text=True,
        )
        signature = display.stderr.splitlines()
        if display.returncode == 1 and signature == [f"{path}: code object is not signed at all"]:
            return None
        if display.returncode == 0 and "Signature=adhoc" in signature:
            return None
        raise RecoveryError("Unable to classify the source app for exact lifecycle recovery.")

    inspected = subprocess.run(
        [str(inspector), str(path)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=120, check=False, text=True,
    )
    hashes = re.findall(r"^artifact_cdhash=([0-9a-fA-F]{40})$", inspected.stdout, re.MULTILINE)
    if inspected.returncode == 0 and len(hashes) == 1:
        return hashes[0].lower()
    return inspect_app(path, None)


def require_exact_app(path, inspector, expected):
    if inspect_app(path, inspector) != expected:
        raise RecoveryError("The stored recovery app failed exact signed identity verification.")


def require_ignored(root, cache):
    result = subprocess.run(
        ["/usr/bin/git", "-C", str(root), "check-ignore", "--quiet", "--", str(cache)],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=10, check=False,
    )
    if result.returncode != 0:
        raise RecoveryError("The local development recovery cache must be ignored by Git.")


def publish(source_parent, source, destination_parent, destination):
    rename = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True).renameatx_np
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    # Darwin renameatx_np(2): RENAME_EXCL refuses even an empty destination.
    if rename(source_parent, os.fsencode(source), destination_parent, os.fsencode(destination), 0x4) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    os.fsync(destination_parent)


def entry_exists(parent, name):
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def copy_entries(slot, source_fd, destination_fd, entries):
    for name, (info, descendants) in entries.items():
        mode = stat.S_IMODE(info.st_mode)
        with slot.open_entry(source_fd, name, info) as source:
            if descendants is None:
                with os.fdopen(os.dup(source), "rb") as reader, os.fdopen(
                    os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                            0o600, dir_fd=destination_fd), "wb"
                ) as writer:
                    shutil.copyfileobj(reader, writer)
                    writer.flush()
                    os.fchmod(writer.fileno(), mode)
                    os.fsync(writer.fileno())
            else:
                os.mkdir(name, 0o700, dir_fd=destination_fd)
                child = os.open(name, slot.directory_flags, dir_fd=destination_fd)
                try:
                    copy_entries(slot, source, child, descendants)
                    os.fchmod(child, mode)
                    os.fsync(child)
                finally:
                    os.close(child)
            slot.require_unchanged(info, os.fstat(source))


@contextmanager
def stage(slot, parent, label):
    name = f".{label}-{secrets.token_hex(12)}"
    os.mkdir(name, 0o700, dir_fd=parent)
    fd = os.open(name, slot.directory_flags, dir_fd=parent)
    info = os.fstat(fd)

    def check():
        slot.revalidate_anchors()
        slot.require_identity(info, slot.entry_info(parent, name))
        slot.require_identity(info, os.fstat(fd))

    try:
        yield name, fd, check
    finally:
        try:
            if entry_exists(parent, name):
                check()
                entries = slot.snapshot(fd)
                slot.dispose_contents(fd, entries, check)
                check()
                os.rmdir(name, dir_fd=parent)
        finally:
            os.close(fd)


def has_executable(entries, path):
    for name in path[:-1]:
        entry = entries.get(name)
        if entry is None or entry[1] is None:
            return False
        entries = entry[1]
    entry = entries.get(path[-1])
    return entry is not None and entry[1] is None


def preserve(slot, stack, app_fd, app_path, root_fd, inspector):
    slot.revalidate_anchors()
    app_entries = slot.snapshot(app_fd)
    if inspector.name == "inspect-pilot-artifact.sh":
        contents = ("Contents",)
        host = (*contents, "MacOS", "DNIeTokenHost")
        plugin = (*contents, "PlugIns", "DNIeTokenExtension.appex",
                  "Contents", "MacOS", "DNIeTokenExtension")
        # Interrupted Xcode output with a missing required executable cannot
        # satisfy the existing exact production recovery inspector.
        if not has_executable(app_entries, host) or not has_executable(app_entries, plugin):
            return False
    expected = inspect_app(app_path, inspector)
    if expected is None:
        return False
    slot.revalidate_anchors()

    cache_path = slot.repository.joinpath(*CACHE)
    require_ignored(slot.repository, cache_path)
    cache_fd = slot.open_directories(stack, root_fd, CACHE, create=True, private_last=True)
    if entry_exists(cache_fd, expected):
        with slot.scoped_anchors():
            archived = slot.open_directories(stack, cache_fd, (expected, APP), private_first=True)
            if archived is None or set(os.listdir(slot.anchors[-2][2])) != {APP}:
                raise RecoveryError("The exact development recovery entry contains unrelated data.")
            slot.snapshot(archived)
            require_exact_app(cache_path / expected / APP, inspector, expected)
            slot.revalidate_anchors()
        return True

    with stage(slot, cache_fd, "recover-source") as (pending, pending_fd, check):
        os.mkdir(APP, 0o700, dir_fd=pending_fd)
        copy_fd = os.open(APP, slot.directory_flags, dir_fd=pending_fd)
        try:
            copy_entries(slot, app_fd, copy_fd, app_entries)
            os.fchmod(copy_fd, stat.S_IMODE(os.fstat(app_fd).st_mode))
            os.fsync(copy_fd)
        finally:
            os.close(copy_fd)
        require_exact_app(cache_path / pending / APP, inspector, expected)
        require_exact_app(app_path, inspector, expected)
        check()
        slot.require_unchanged(slot.entry_info(pending_fd, APP), (cache_path / pending / APP).lstat())
        os.fsync(pending_fd)
        publish(cache_fd, pending, cache_fd, expected)
    return True


def restore(slot, stack, root_fd, inspector, expected, source_parts):
    if HEX.fullmatch(expected) is None:
        raise RecoveryError("Development source restoration requires one exact signed identity.")

    cache_path = slot.repository.joinpath(*CACHE)
    cache_fd = slot.open_directories(stack, root_fd, CACHE, create=False, private_last=True)
    if cache_fd is None:
        return False
    require_ignored(slot.repository, cache_path)
    archived = slot.open_directories(stack, cache_fd, (expected, APP), private_first=True)
    if archived is None or set(os.listdir(slot.anchors[-2][2])) != {APP}:
        raise RecoveryError("No complete exact signed app is available for development source recovery.")
    archived_path = cache_path / expected / APP
    archived_info = os.fstat(archived)
    entries = slot.snapshot(archived)
    require_exact_app(archived_path, inspector, expected)
    slot.revalidate_anchors()

    parent_parts = ("DerivedData", "T067", *source_parts[:-1])
    parent = slot.open_directories(stack, root_fd, parent_parts, create=True)
    if entry_exists(parent, APP):
        raise RecoveryError("A source app already occupies the recovery destination; it was preserved.")

    with stage(slot, parent, "restore-source") as (pending, pending_fd, check):
        # Preserve the bundle name for strict signature verification.
        os.mkdir(APP, 0o700, dir_fd=pending_fd)
        copy_fd = os.open(APP, slot.directory_flags, dir_fd=pending_fd)
        try:
            copy_entries(slot, archived, copy_fd, entries)
            os.fchmod(copy_fd, stat.S_IMODE(archived_info.st_mode))
            os.fsync(copy_fd)
        finally:
            os.close(copy_fd)
        require_exact_app(slot.repository.joinpath(*parent_parts, pending, APP), inspector, expected)
        slot.require_unchanged(archived_info, os.fstat(archived))
        check()
        publish(pending_fd, APP, parent, APP)
    return True


def prune(slot, stack, root_fd, inspector, expected, source_parts, observe_use):
    if HEX.fullmatch(expected) is None:
        raise RecoveryError("Development recovery disposition requires one exact signed identity.")
    cache_path = slot.repository.joinpath(*CACHE)
    cache_fd = slot.open_directories(stack, root_fd, CACHE, create=False, private_last=True)
    if cache_fd is None or not entry_exists(cache_fd, expected):
        return False
    require_ignored(slot.repository, cache_path)
    archive = slot.open_directories(stack, cache_fd, (expected, APP), private_first=True)
    if archive is None or set(os.listdir(slot.anchors[-2][2])) != {APP}:
        raise RecoveryError("The exact development recovery entry contains unrelated data.")
    entry_fd = slot.anchors[-2][2]
    archive_path = cache_path / expected
    entries = slot.snapshot(entry_fd)
    require_exact_app(archive_path / APP, inspector, expected)
    observe_use(archive_path)
    # Drop the archive app anchor before disposing of it, but keep the
    # independently verified original source anchored throughout disposal.
    del slot.anchors[-1:]
    source = slot.open_directories(stack, root_fd, ("DerivedData", "T067", *source_parts))
    if source is None:
        raise RecoveryError("The exact original source is missing; the recovery copy was retained.")
    slot.snapshot(source)
    require_exact_app(slot.path.joinpath(*source_parts), inspector, expected)
    slot.retire_and_dispose(cache_fd, expected, entry_fd, entries, "recovery", publish)
    return True
