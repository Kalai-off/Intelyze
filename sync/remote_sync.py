import subprocess
import shutil
import os
import pathlib

# Try to import boto3; if not available we'll fall back to rclone
try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except Exception:
    boto3 = None

def _upload_dir_to_s3(s3_client, bucket, prefix, local_dir: str):
    local_dir = pathlib.Path(local_dir)
    for root, _, files in os.walk(local_dir):
        root_p = pathlib.Path(root)
        for f in files:
            full = root_p / f
            rel = full.relative_to(local_dir)
            key = f"{prefix.rstrip('/')}/{rel.as_posix()}"
            try:
                s3_client.upload_file(str(full), bucket, key)
                print(f"remote_sync(s3): uploaded {full} → s3://{bucket}/{key}")
            except Exception as e:
                print(f"remote_sync(s3): failed to upload {full}: {e}")

def _upload_file_to_s3(s3_client, bucket, prefix, local_file: str):
    """Upload a single file to S3. If prefix contains '/', use it as-is; otherwise nest under prefix."""
    local_file = pathlib.Path(local_file)
    # If prefix looks like a full path (contains /), use it directly; otherwise nest the filename
    if "/" in prefix or prefix.endswith(local_file.name):
        key = prefix
    else:
        key = f"{prefix.rstrip('/')}/{local_file.name}"
    try:
        s3_client.upload_file(str(local_file), bucket, key)
        print(f"remote_sync(s3): uploaded {local_file} → s3://{bucket}/{key}")
    except Exception as e:
        print(f"remote_sync(s3): failed to upload {local_file}: {e}")

def sync_path(local_path: str | pathlib.Path, remote_subpath: str | None = None, remote_name: str | None = None):
    """
    Try S3 upload first (if boto3 and AWS credentials present), otherwise fallback to rclone copy.
    - local_path: folder or file to copy
    - remote_subpath: path used on remote (for S3 this becomes the S3 key/prefix; for rclone it becomes remote:path)
    - remote_name: for rclone this is the remote name; for S3 this can be "bucket" if provided
    Returns True if any sync was attempted, False otherwise.
    """
    local = str(local_path)
    if not os.path.exists(local):
        print("remote_sync: local path does not exist:", local)
        return False

    # Attempt S3 when boto3 available and credentials (or bucket) provided via env/remote_name
    try:
        if boto3 is not None:
            # Determine bucket and prefix:
            bucket = remote_name or os.environ.get("SYNC_S3_BUCKET") or os.environ.get("AWS_S3_BUCKET")
            prefix = remote_subpath or pathlib.Path(local).name
            # Basic check for AWS creds in env (will also be read from standard AWS config)
            has_aws = any(os.environ.get(k) for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")) or bucket
            if has_aws and bucket:
                try:
                    s3 = boto3.client("s3")
                    if os.path.isdir(local):
                        _upload_dir_to_s3(s3, bucket, prefix, local)
                    else:
                        _upload_file_to_s3(s3, bucket, prefix, local)
                    print(f"remote_sync: completed upload to s3://{bucket}/{prefix}")
                    return True
                except (BotoCoreError, ClientError, Exception) as e:
                    print("remote_sync: S3 upload failed, falling back to rclone if available:", e)
    except Exception as _e:
        print("remote_sync: S3 attempt error:", _e)

    # Fallback to rclone if available
    rclone_bin = shutil.which("rclone")
    if not rclone_bin:
        print("remote_sync: neither boto3/S3 successful nor rclone found; skipping sync")
        return False

    remote = (remote_name or os.environ.get("RCLONE_REMOTE") or "").rstrip(":")
    if not remote:
        print("remote_sync: RCLONE_REMOTE not set and no remote_name provided; skipping rclone sync")
        return False

    dest_sub = remote_subpath or pathlib.Path(local).name
    dest = f"{remote}:{dest_sub}"

    try:
        cmd = [rclone_bin, "copy", local, dest, "--create-empty-src-dirs", "--transfers", "4"]
        print(f"remote_sync: running {' '.join(cmd)}")
        subprocess.run(cmd, check=False)
        return True
    except Exception as e:
        print(f"remote_sync: rclone sync failed: {e}")
        return False
