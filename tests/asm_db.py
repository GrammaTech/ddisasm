import os
import hashlib
import platform
from enum import Enum

import distro


class DB:
    """Singleton database connection wrapper."""

    class State(Enum):
        NEW = 1
        CONNECTED = 2
        ERROR = 3

    conn = None
    state = State.NEW

    def __new__(cls):
        if cls.state == DB.State.NEW:
            connect_uri = os.environ.get("DATABASE_URL")

            if not connect_uri:
                cls.state = DB.State.ERROR
                return None

            try:
                psycopg2 = __import__("psycopg2")
                cls.conn = psycopg2.connect(connect_uri)
                cls.state = DB.State.CONNECTED
            except (ImportError, psycopg2.Error) as ex:
                print(ex)
                cls.state = DB.State.ERROR

        return cls.conn


def upload(name, asm, compilers, compiler_args, strip):
    conn = DB()
    if conn:
        cursor = conn.cursor()

        # Upsert assembly contents to the `assembly' table.
        with open(asm, "r") as f:
            contents = f.read()
            checksum = hashlib.md5(contents.encode("utf-8")).hexdigest()
            cursor.execute(
                """
                INSERT INTO assembly (checksum, content)
                VALUES (%s, %s)
                ON CONFLICT (checksum)
                DO UPDATE SET updated_at = NOW()
                RETURNING assembly_id
            """,
                (checksum, contents),
            )
            assembly_id = cursor.fetchone()[0]

        # Insert disassembly details into the `disassembled' table.
        cursor.execute(
            """
            INSERT INTO disassembled (
                name,
                assembly_id,
                compiler,
                compiler_args,
                platform,
                distro,
                ci_job_image,
                ci_pipeline_id,
                ci_commit_sha,
                ci_commit_before_sha,
                ci_commit_branch,
                ci_commit_ref_slug,
                strip
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
            (
                name,
                assembly_id,
                " ".join(compilers),
                " ".join(compiler_args),
                platform.system(),
                " ".join([distro.name(), distro.version()]),
                os.environ.get("CI_JOB_IMAGE"),
                os.environ.get("CI_PIPELINE_ID"),
                os.environ.get("CI_COMMIT_SHA"),
                os.environ.get("CI_COMMIT_BEFORE_SHA"),
                os.environ.get("CI_COMMIT_BRANCH"),
                os.environ.get("CI_COMMIT_REF_SLUG"),
                strip,
            ),
        )

        conn.commit()
