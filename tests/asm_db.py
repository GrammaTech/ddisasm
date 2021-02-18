import os
import hashlib
from enum import Enum


class State(Enum):
    NEW = 1
    CONNECTED = 2
    ERROR = 3


__db = None
__db_state = State.NEW

# FIXME:
try:
    import psycopg2
except ImportError:
    __db_state = State.ERROR


def db():
    global __db
    global __db_state

    if __db_state == State.NEW:
        connect_uri = os.environ.get("DATABASE_URL")

        if not connect_uri:
            __db_state = State.ERROR
            return None

        try:
            __db = psycopg2.connect(connect_uri)
            __db_state = State.CONNECTED
        except psycopg2.Error as ex:
            print(ex)
            __db_state = State.ERROR

    return __db


def upload(name, asm, compilers, compiler_args):
    conn = db()
    if conn:
        cursor = conn.cursor()

        # Upsert assembly contents to the `assembly' table.
        with open(asm, "rb") as f:
            contents = f.read()
            checksum = hashlib.md5(contents).hexdigest()
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
                ci_job_image,
                ci_pipeline_id,
                ci_commit_sha,
                ci_commit_before_sha,
                ci_commit_branch,
                ci_commit_ref_slug
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
            (
                name,
                assembly_id,
                " ".join(compilers),
                " ".join(compiler_args),
                os.environ.get("CI_JOB_IMAGE"),
                os.environ.get("CI_PIPELINE_ID"),
                os.environ.get("CI_COMMIT_SHA"),
                os.environ.get("CI_COMMIT_BEFORE_SHA"),
                os.environ.get("CI_COMMIT_BRANCH"),
                os.environ.get("CI_COMMIT_REF_SLUG"),
            ),
        )

        conn.commit()
